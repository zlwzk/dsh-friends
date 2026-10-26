// dsh-friends —— browser half（自包含手写 bundle，无 import/export/JSX/构建步骤）。
//
// 挂载：左侧栏一个「鲸友」图标 + 面板。
// 数据流：
//   host 路由 /dsh-friends/state|profile|friends  —— 本机资料/任务状态持久化
//   浏览器直连公共 MQTT-over-WSS（emqx/hivemq）   —— 好友实时在线
//   payload AES-GCM 端到端加密，密钥由好友码派生   —— broker 只见密文
//
// 消息协议（加密前的 JSON，kind 区分）：
//   presence  { kind, id, nickname, signature, mood, status, label, idleSec, ts }
//   poke      { kind, from, emoji, ts }                         戳一戳
//   bye       { kind, id, ts }                                  主动下线
// 状态 status: online | busy | error
//
// 主题：发布到 dshf/u/<对方好友码>，订阅 dshf/u/<自己好友码>。
window.__ModuleLoader__.load({
  id: 'dsh-friends',
  factory: (require) => {
    const module = { exports: {} }
    const exports = module.exports
    Object.defineProperty(exports, Symbol.toStringTag, { value: 'Module' })

    const React = require('react')
    const h = React.createElement

    const PANEL_ID = 'dsh-friends'
    const CONFIG_ROW_ID = 'dsh-friends'
    const API = '/dsh-friends'
    const BROKERS = ['wss://broker.emqx.io:8084/mqtt', 'wss://broker.hivemq.com:8884/mqtt']
    const HEARTBEAT_MS = 8000
    const OFFLINE_AFTER_MS = 26000 // 3 个心跳没见着即离线

    // ============================================================ MQTT (qos0)

    function encStr(buf) {
      const o = new Uint8Array(2 + buf.length)
      o[0] = (buf.length >> 8) & 0xff
      o[1] = buf.length & 0xff
      o.set(buf, 2)
      return o
    }
    function encRL(len) {
      const b = []
      do { let x = len % 128; len = Math.floor(len / 128); if (len > 0) x |= 0x80; b.push(x) } while (len > 0)
      return new Uint8Array(b)
    }
    function cat(list) {
      let n = 0; for (const x of list) n += x.length
      const o = new Uint8Array(n); let p = 0
      for (const x of list) { o.set(x, p); p += x.length }
      return o
    }
    function pkt(type, body, flags) {
      return cat([new Uint8Array([(type << 4) | (flags || 0)]), encRL(body.length), body])
    }

    function createMqtt(url, clientId, onMessage, onStatus) {
      let ws = null, connected = false, gone = false, ping = null, retry = null, delay = 800
      const subs = new Set(); let pid = 0
      const status = (s, d) => { try { onStatus && onStatus(s, d) } catch (e) {} }
      function connect() {
        if (gone) return
        try { ws = new WebSocket(url, ['mqtt']) } catch (e) { schedule(e); return }
        ws.binaryType = 'arraybuffer'
        ws.onopen = () => {
          const v = cat([encStr(new TextEncoder().encode('MQTT')), new Uint8Array([4, 2, 0, 25]),
            encStr(new TextEncoder().encode(clientId))])
          ws.send(pkt(1, v))
        }
        ws.onmessage = (ev) => {
          const d = new Uint8Array(ev.data)
          if (d.length < 2) return
          const type = d[0] >> 4
          if (type === 2) {
            if (d[3] !== 0) { status('rejected', d[3]); try { ws.close() } catch (e) {} return }
            connected = true; delay = 800; status('connected')
            for (const t of Array.from(subs)) sendSub(t)
            clearInterval(ping)
            ping = setInterval(() => { if (connected && ws && ws.readyState === 1) try { ws.send(pkt(12, new Uint8Array(0))) } catch (e) {} }, 20000)
          } else if (type === 3) {
            // 解析剩余长度
            let mult = 1, val = 0, p = 1, consumed = 0
            do { const b = d[p]; val += (b & 127) * mult; mult *= 128; consumed = p; if (!(b & 128)) break; p++ } while (true)
            let i = consumed + 1
            const tl = (d[i] << 8) | d[i + 1]; i += 2
            const topic = new TextDecoder().decode(d.slice(i, i + tl)); i += tl
            try { onMessage(topic, d.slice(i)) } catch (e) {}
          }
        }
        ws.onerror = () => {}
        ws.onclose = () => { connected = false; clearInterval(ping); if (!gone) schedule() }
      }
      function schedule(e) {
        if (gone) return
        status('reconnecting', e && e.message)
        clearTimeout(retry)
        retry = setTimeout(() => { delay = Math.min(delay * 1.6, 15000); connect() }, delay)
      }
      function sendSub(t) {
        if (!connected || !ws || ws.readyState !== 1) return
        pid = (pid % 65535) + 1
        const body = cat([new Uint8Array([pid >> 8, pid & 255]), encStr(new TextEncoder().encode(t)), new Uint8Array([0])])
        ws.send(pkt(8, body, 2))
      }
      return {
        start() { gone = false; connect() },
        subscribe(t) { subs.add(t); if (connected) sendSub(t) },
        connected() { return connected },
        currentUrl() { return url },
        publish(t, payload) {
          if (!connected || !ws || ws.readyState !== 1) return false
          ws.send(pkt(3, cat([encStr(new TextEncoder().encode(t)), payload]))); return true
        },
        stop() {
          gone = true; clearInterval(ping); clearTimeout(retry)
          try { if (connected && ws) ws.send(pkt(14, new Uint8Array(0))) } catch (e) {}
          try { ws && ws.close() } catch (e) {}
          connected = false
        },
      }
    }

    // ============================================================ AES-GCM

    const te = new TextEncoder(), td = new TextDecoder()
    let keyCache = new Map()
    async function keyFor(code) {
      const C = String(code).toUpperCase()
      if (keyCache.has(C)) return keyCache.get(C)
      const subtle = crypto.subtle
      const material = await subtle.importKey('raw', te.encode('dsh-friends/v1:' + C), 'HKDF', false, ['deriveKey'])
      const key = await subtle.deriveKey(
        { name: 'HKDF', hash: 'SHA-256', salt: te.encode('dsh-friends-presence'), info: te.encode('aes-gcm') },
        material, { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt'])
      keyCache.set(C, key)
      return key
    }
    async function seal(obj, code) {
      const iv = crypto.getRandomValues(new Uint8Array(12))
      const ct = new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, await keyFor(code), te.encode(JSON.stringify(obj))))
      return b64(cat([iv, ct]))
    }
    async function open(b64str, code) {
      try {
        const all = unb64(b64str)
        const plain = new Uint8Array(await crypto.subtle.decrypt({ name: 'AES-GCM', iv: all.slice(0, 12) }, await keyFor(code), all.slice(12)))
        return JSON.parse(td.decode(plain))
      } catch (e) { return null }
    }
    function b64(bytes) { let s = ''; for (let i = 0; i < bytes.length; i++) s += String.fromCharCode(bytes[i]); return btoa(s) }
    function unb64(s) { const bin = atob(s); const o = new Uint8Array(bin.length); for (let i = 0; i < bin.length; i++) o[i] = bin.charCodeAt(i); return o }
    function validCode(c) { return typeof c === 'string' && /^[A-HJ-NP-Z2-9]{6}$/.test(String(c).toUpperCase()) }

    // ============================================================ host API

    async function apiGet(path) {
      const r = await fetch(API + path, { headers: { accept: 'application/json' } })
      if (!r.ok) throw new Error('HTTP ' + r.status)
      return r.json()
    }
    async function apiPost(path, body) {
      const r = await fetch(API + path, {
        method: 'POST',
        headers: { 'content-type': 'application/json', accept: 'application/json' },
        body: JSON.stringify(body || {}),
      })
      if (!r.ok) throw new Error('HTTP ' + r.status)
      return r.json()
    }

    // ============================================================ styles

    const CSS = `
.dshf-wrap{display:flex;flex-direction:column;height:100%;font-size:13px;color:var(--dsh-fg,#e8eaed)}
.dshf-head{padding:12px 14px 8px}
.dshf-title{display:flex;align-items:center;gap:8px;font-weight:600;font-size:14px}
.dshf-conn{font-size:11px;opacity:.65;margin-top:2px}
.dshf-conn.ok{color:#37d67a;opacity:1}
.dshf-conn.bad{color:#ffb454}
.dshf-me{margin:0 12px 10px;padding:10px 12px;border-radius:12px;background:var(--dsh-card,rgba(120,140,170,.12))}
.dshf-me-row{display:flex;align-items:center;gap:8px}
.dshf-mood{font-size:20px;line-height:1}
.dshf-nick{font-weight:600}
.dshf-code{margin-left:auto;font-family:ui-monospace,Menlo,Consolas,monospace;font-size:12px;background:rgba(90,183,255,.16);color:#7cc2ff;padding:2px 7px;border-radius:7px;cursor:pointer;user-select:none}
.dshf-sign{margin-top:6px;opacity:.82;line-height:1.4;word-break:break-word}
.dshf-task{margin-top:6px;font-size:11px;display:flex;align-items:center;gap:6px}
.dshf-actions{display:flex;gap:6px;margin:8px 12px 0;flex-wrap:wrap}
.dshf-btn{font-size:12px;padding:5px 10px;border-radius:8px;border:1px solid var(--dsh-border,rgba(140,160,190,.28));background:transparent;color:inherit;cursor:pointer}
.dshf-btn:hover{background:rgba(120,140,170,.16)}
.dshf-btn.primary{background:#2f7cf6;border-color:#2f7cf6;color:#fff}
.dshf-sec{padding:6px 14px 2px;font-size:11px;opacity:.55;letter-spacing:.04em;text-transform:uppercase}
.dshf-list{flex:1;overflow:auto;margin:4px 8px 12px;padding:0 6px}
.dshf-f{display:flex;align-items:flex-start;gap:9px;padding:9px 8px;border-radius:11px}
.dshf-f:hover{background:rgba(120,140,170,.1)}
.dshf-dot{width:9px;height:9px;border-radius:50%;margin-top:5px;flex:0 0 auto;box-shadow:0 0 0 2px rgba(0,0,0,.08)}
.dshf-dot.online{background:#37d67a}.dshf-dot.busy{background:#ffc043}.dshf-dot.error{background:#ff5d5d}.dshf-dot.offline{background:#8a94a6}
.dshf-f-main{min-width:0;flex:1}
.dshf-f-line{display:flex;align-items:baseline;gap:7px}
.dshf-f-name{font-weight:600;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.dshf-f-state{font-size:11px;opacity:.62;white-space:nowrap}
.dshf-f-sign{font-size:11px;opacity:.8;margin-top:2px;line-height:1.35;word-break:break-word;display:-webkit-box;-webkit-line-clamp:2;-webkit-box-orient:vertical;overflow:hidden}
.dshf-f-actions{display:flex;gap:4px;opacity:0;transition:opacity .12s;flex:0 0 auto}
.dshf-f:hover .dshf-f-actions{opacity:1}
.dshf-mini{font-size:13px;padding:2px 5px;border-radius:6px;cursor:pointer;border:none;background:transparent}
.dshf-mini:hover{background:rgba(120,140,170,.2)}
.dshf-empty{padding:26px 18px;text-align:center;opacity:.55;line-height:1.6;font-size:12px}
.dshf-empty b{opacity:.9;font-weight:600}
.dshf-inputrow{display:flex;gap:6px;margin:8px 12px}
.dshf-input{flex:1;min-width:0;font:inherit;font-size:12px;padding:7px 9px;border-radius:8px;border:1px solid var(--dsh-border,rgba(140,160,190,.3));background:transparent;color:inherit}
.dshf-input::placeholder{opacity:.5}
.dshf-edit{margin:0 12px 10px;padding:10px;background:var(--dsh-card,rgba(120,140,170,.1));border-radius:10px}
.dshf-edit .dshf-input{margin-bottom:6px;width:100%;box-sizing:border-box}
.dshf-poke{position:fixed;font-size:26px;pointer-events:none;z-index:9999;animation:dshf-float 1.6s ease-out forwards}
@keyframes dshf-float{0%{opacity:0;transform:translateY(8px) scale(.6)}18%{opacity:1;transform:translateY(0) scale(1.15)}100%{opacity:0;transform:translateY(-64px) scale(1)}}
.dshf-hint{font-size:11px;opacity:.55;padding:0 14px 12px;line-height:1.5}
`

    // ============================================================ presence store

    // 一个好友 = 一个好友码。在线状态来自 presence 心跳；戳一戳是即时事件。
    function createStore() {
      const listeners = new Set()
      const state = {
        me: null, // {id,nickname,signature,mood,code,friends,task}
        friends: new Map(), // code -> {code,alias,online,status,label,nickname,signature,mood,lastSeen,idleSec}
        conn: 'connecting', // connecting|connected|reconnecting|rejected|unsupported
        brokerIdx: 0,
        pokes: [], // 收到的戳一戳动画 {key,emoji,x,y}
      }
      let mqtt = null
      let hbTimer = null
      let refreshTimer = null

      function emit() { for (const l of Array.from(listeners)) { try { l() } catch (e) {} } }
      function subscribe(l) { listeners.add(l); return () => listeners.delete(l) }

      async function refreshMe() {
        try {
          state.me = await apiGet('/state')
          reconcileFriends()
          emit()
          return true
        } catch (e) { return false }
      }

      function reconcileFriends() {
        if (!state.me) return
        const codes = new Set(state.me.friends.map((f) => f.code))
        // 删除不再是好友的
        for (const code of Array.from(state.friends.keys())) {
          if (!codes.has(code)) state.friends.delete(code)
        }
        // 补别名
        for (const f of state.me.friends) {
          const cur = state.friends.get(f.code)
          if (cur) cur.alias = f.alias
          else state.friends.set(f.code, { code: f.code, alias: f.alias || '', online: false, status: 'offline', nickname: '', signature: '', mood: '🐳', label: '', lastSeen: 0, idleSec: -1 })
        }
      }

      function topicFor(code) { return 'dshf/u/' + String(code).toUpperCase() }

      // 并发探测候选 broker，返回第一个能完成 MQTT 握手的 url。
      // 公共 broker 会区域性不可达（实测 emqx 在部分时段完全超时），启动时
      // 死磕第一个会让用户白等几十秒；全部失败则抛错，由外层安排重试。
      // exclude：手动换节点时排除当前节点；若排除后无候选则回退全量。
      function pickBroker(timeoutMs, exclude) {
        const candidates = exclude
          ? (BROKERS.filter((u) => u !== exclude).length ? BROKERS.filter((u) => u !== exclude) : BROKERS)
          : BROKERS
        return new Promise((resolve, reject) => {
          let settled = false, pending = candidates.length
          const finish = (v, e) => {
            if (settled) return
            settled = true
            if (e) reject(e); else resolve(v)
          }
          for (const url of candidates) {
            let ws = null, done = false
            const timer = setTimeout(() => {
              if (done) return
              done = true; try { ws && ws.close() } catch (e) {}
              if (--pending === 0) finish(null, new Error('所有公共中继均不可达'))
            }, timeoutMs)
            try { ws = new WebSocket(url, ['mqtt']) } catch (e) {
              done = true; clearTimeout(timer)
              if (--pending === 0) finish(null, e)
              continue
            }
            ws.binaryType = 'arraybuffer'
            ws.onopen = () => {
              const v = cat([encStr(te.encode('MQTT')), new Uint8Array([4, 2, 0, 25]),
                encStr(te.encode('dshf-probe-' + Math.random().toString(36).slice(2, 8)))])
              try { ws.send(pkt(1, v)) } catch (e) {}
            }
            ws.onmessage = (ev) => {
              if (done) return
              const d = new Uint8Array(ev.data)
              if ((d[0] >> 4) !== 2) return
              done = true; clearTimeout(timer); try { ws.close() } catch (e) {}
              if (d[d.length - 1] === 0) finish(url, null)
              else if (--pending === 0) finish(null, new Error('所有公共中继均拒绝连接'))
            }
            ws.onerror = () => {}
            ws.onclose = () => {
              if (done) return
              done = true; clearTimeout(timer)
              if (--pending === 0) finish(null, new Error('所有公共中继均不可达'))
            }
          }
        })
      }

      async function startRelay(exclude) {
        if (mqtt) mqtt.stop()
        const own = state.me.code
        // 探测（最多 6 秒）；失败时回退到排除项之外/第一个，交给重连逻辑。
        let url = exclude || BROKERS[state.brokerIdx % BROKERS.length]
        try { url = await pickBroker(6000, exclude) } catch (e) { /* 用回退 url 继续 */ }
        state.brokerIdx = BROKERS.indexOf(url)
        if (state.brokerIdx < 0) state.brokerIdx = 0
        const clientId = 'dshf-' + state.me.id.slice(0, 10) + '-' + Math.random().toString(36).slice(2, 6)
        mqtt = createMqtt(url, clientId, handleMessage, (s) => {
          state.conn = s
          if (s === 'rejected' || s === 'reconnecting') {
            // rejected 说明这个节点不让我们上，换一个（排除当前）；网络抖动则
            // 由指数退避自然重连。
            if (s === 'rejected') setTimeout(() => startRelay(url), 200)
          }
          emit()
        })
        mqtt.start()
        mqtt.subscribe(topicFor(own))

        clearInterval(hbTimer)
        hbTimer = setInterval(sendPresence, HEARTBEAT_MS)
        setTimeout(sendPresence, 600)
      }

      function currentStatus() {
        const t = state.me && state.me.task
        if (t && t.active) return t.error ? 'error' : 'busy'
        return 'online'
      }

      async function sendPresence() {
        if (!mqtt || !state.me) return
        if (!mqtt.connected()) return
        const t = state.me.task
        const msg = {
          kind: 'presence',
          id: state.me.id,
          nickname: state.me.nickname,
          signature: state.me.signature,
          mood: state.me.mood,
          status: currentStatus(),
          label: t && t.active ? (t.label || '') : '',
          ts: Date.now(),
        }
        // 给每个好友各发一份（用对方的码加密）
        for (const f of state.me.friends) {
          try {
            const sealed = await seal(msg, f.code)
            mqtt.publish(topicFor(f.code), new TextEncoder().encode(sealed))
          } catch (e) {}
        }
      }

      async function sendBye() {
        if (!mqtt || !state.me) return
        for (const f of state.me.friends) {
          try { mqtt.publish(topicFor(f.code), new TextEncoder().encode(await seal({ kind: 'bye', id: state.me.id, ts: Date.now() }, f.code))) } catch (e) {}
        }
      }

      async function handleMessage(topic, payloadBytes) {
        if (!state.me) return
        const text = new TextDecoder().decode(payloadBytes)
        // 主题形如 dshf/u/<OWN>；任何一个好友都可能往这里发，逐个尝试解密
        for (const f of state.me.friends) {
          const msg = await open(text, f.code)
          if (!msg) continue
          const friend = state.friends.get(f.code)
          if (!friend) continue
          if (msg.kind === 'presence') {
            friend.online = true
            friend.status = msg.status === 'busy' ? 'busy' : msg.status === 'error' ? 'error' : 'online'
            friend.label = msg.label || ''
            friend.nickname = msg.nickname || friend.nickname
            friend.signature = msg.signature || ''
            friend.mood = msg.mood || '🐳'
            friend.id = msg.id
            friend.lastSeen = Date.now()
            emit()
          } else if (msg.kind === 'bye') {
            friend.online = false; friend.status = 'offline'; friend.lastSeen = Date.now(); emit()
          } else if (msg.kind === 'poke') {
            friend.online = true; friend.lastSeen = Date.now()
            const key = Math.random().toString(36).slice(2)
            state.pokes.push({ key, emoji: msg.emoji || '👉', from: friend.alias || friend.nickname || f.code })
            emit()
            setTimeout(() => { state.pokes = state.pokes.filter((p) => p.key !== key); emit() }, 1700)
          }
          return // 一份密文只可能被一个好友码解开
        }
      }

      async function poke(code) {
        if (!mqtt || !state.me) return
        const emojis = ['👉', '🐟', '💧', '❤️', '🫧', '⚡']
        const emoji = emojis[Math.floor(Math.random() * emojis.length)]
        const sealed = await seal({ kind: 'poke', from: state.me.id, emoji, ts: Date.now() }, code)
        mqtt.publish(topicFor(code), new TextEncoder().encode(sealed))
        return emoji
      }

      async function updateProfile(patch) {
        const saved = await apiPost('/profile', patch)
        await refreshMe()
        sendPresence()
        return saved
      }

      async function addFriend(code, alias) {
        code = String(code).toUpperCase()
        if (!validCode(code)) throw new Error('好友码应为 6 位字母数字')
        if (state.me && code === state.me.code) throw new Error('不能加自己为好友')
        const friends = (state.me ? state.me.friends : []).slice()
        if (friends.some((f) => f.code === code)) throw new Error('已经是好友了')
        friends.push({ code, alias: alias || '' })
        await apiPost('/friends', { friends })
        await refreshMe()
        sendPresence()
      }

      async function removeFriend(code) {
        const friends = state.me.friends.filter((f) => f.code !== code)
        await apiPost('/friends', { friends })
        state.friends.delete(code)
        await refreshMe()
        sendPresence()
      }

      // 定期把超时没心跳的好友标记离线
      function offlineSweep() {
        const now = Date.now()
        let changed = false
        for (const fr of state.friends.values()) {
          if (fr.online && now - fr.lastSeen > OFFLINE_AFTER_MS) {
            fr.online = false; fr.status = 'offline'; changed = true
          }
          if (fr.online) fr.idleSec = Math.max(0, Math.round((now - fr.lastSeen) / 1000))
        }
        if (changed) emit()
      }

      window.addEventListener('beforeunload', sendBye)
      window.addEventListener('pagehide', sendBye)

      return {
        state, subscribe,
        async init() {
          await refreshMe()
          await startRelay()
          clearInterval(refreshTimer)
          refreshTimer = setInterval(() => { refreshMe(); offlineSweep() }, 5000)
        },
        updateProfile, addFriend, removeFriend, poke,
        rotateBroker() {
          // 手动换节点：排除当前正在用的那个，逼探测挑另一个。
          const current = mqtt && mqtt.currentUrl ? mqtt.currentUrl() : undefined
          state.brokerIdx++
          startRelay(current)
        },      }
    }

    // ============================================================ components

    const DOT = { online: '🟢', busy: '🟡', error: '🔴', offline: '⚫' }
    const STATE_TEXT = {
      online: '在线', busy: '忙碌中', error: '遇到问题', offline: '离线',
    }

    /** 文案里的行内加粗（空状态说明用）。 */
    function bold(text) { return h('b', { style: { opacity: 0.9, fontWeight: 600 } }, text) }

    function FriendIcon() {
      return h('svg', {
        width: 18, height: 18, viewBox: '0 0 64 64', fill: 'none', 'aria-hidden': 'true', focusable: 'false',
      },
        h('path', { d: 'M40 14c8 0 14 6 14 13 0 6-4 10-9 11l3 5-6-3c-1 0-2 .5-3 .5-3 0-6-1-8-3l4-3c2 1 4 2 6 2 5 0 8-3 8-7s-4-7-9-7c-4 0-7 2-8 5l-5-1c2-7 8-9 13-9Z', fill: 'currentColor', opacity: '0.55' }),
        h('path', { d: 'M12 30c0-9 8-16 19-16 9 0 17 6 17 14 0 8-7 14-17 14-2 0-4-.3-6-.8l-7 4 2-7c-5-2-8-6-8-8Z', fill: 'currentColor' }),
        h('circle', { cx: '38', cy: '28', r: '2.2', fill: 'var(--dsh-bg,#11151c)' }),
        h('circle', { cx: '20', cy: '12', r: '4.5', fill: '#37d67a' }),
      )
    }

    function copyText(t) { try { navigator.clipboard && navigator.clipboard.writeText(t) } catch (e) {} }

    function MeCard({ store, editing, setEditing }) {
      const me = store.state.me
      if (!me) return h('div', { className: 'dshf-me' }, '正在读取资料…')
      const t = me.task && me.task.active
      const statusLine = t ? ((me.task.error ? '🔴 ' : '🟡 ') + (me.task.label || '执行任务中')) : '🟢 在线空闲'
      return h('div', { className: 'dshf-me' },
        h('div', { className: 'dshf-me-row' },
          h('span', { className: 'dshf-mood' }, me.mood || '🐳'),
          h('span', { className: 'dshf-nick' }, me.nickname),
          h('span', {
            className: 'dshf-code', title: '点击复制好友码',
            onClick: () => copyText(me.code),
          }, me.code),
        ),
        h('div', { className: 'dshf-sign' }, me.signature),
        h('div', { className: 'dshf-task' }, statusLine),
      )
    }

    function EditCard({ store, onClose }) {
      const me = store.state.me
      const [nick, setNick] = React.useState(me.nickname)
      const [sign, setSign] = React.useState(me.signature)
      const [mood, setMood] = React.useState(me.mood)
      const [busy, setBusy] = React.useState(false)
      const [err, setErr] = React.useState('')
      async function save() {
        setBusy(true); setErr('')
        try { await store.updateProfile({ nickname: nick, signature: sign, mood: mood }); onClose() }
        catch (e) { setErr('保存失败：' + (e.message || e)); setBusy(false) }
      }
      return h('div', { className: 'dshf-edit' },
        h('input', { className: 'dshf-input', value: nick, maxLength: 24, placeholder: '昵称', onChange: (e) => setNick(e.target.value) }),
        h('input', { className: 'dshf-input', value: mood, maxLength: 4, placeholder: '心情 emoji', onChange: (e) => setMood(e.target.value) }),
        h('input', { className: 'dshf-input', value: sign, maxLength: 60, placeholder: '个性签名（有趣一点）', onChange: (e) => setSign(e.target.value) }),
        err ? h('div', { style: { color: '#ff8080', fontSize: 11, marginBottom: 6 } }, err) : null,
        h('div', { style: { display: 'flex', gap: 6 } },
          h('button', { className: 'dshf-btn primary', disabled: busy, onClick: save }, busy ? '保存中…' : '保存'),
          h('button', { className: 'dshf-btn', onClick: onClose }, '取消'),
        ),
      )
    }

    function AddRow({ store }) {
      const [code, setCode] = React.useState('')
      const [alias, setAlias] = React.useState('')
      const [open, setOpen] = React.useState(false)
      const [err, setErr] = React.useState('')
      if (!open) return h('div', { className: 'dshf-actions' },
        h('button', { className: 'dshf-btn primary', onClick: () => setOpen(true) }, '＋ 添加好友'),
      )
      async function add() {
        setErr('')
        try { await store.addFriend(code, alias); setCode(''); setAlias(''); setOpen(false) }
        catch (e) { setErr(e.message || String(e)) }
      }
      return h('div', { className: 'dshf-edit' },
        h('input', { className: 'dshf-input', value: code, maxLength: 6, placeholder: '对方的 6 位好友码', onChange: (e) => setCode(e.target.value.toUpperCase()), style: { textTransform: 'uppercase', letterSpacing: 2 } }),
        h('input', { className: 'dshf-input', value: alias, maxLength: 24, placeholder: '备注名（可选）', onChange: (e) => setAlias(e.target.value) }),
        err ? h('div', { style: { color: '#ff8080', fontSize: 11, marginBottom: 6 } }, err) : null,
        h('div', { style: { display: 'flex', gap: 6 } },
          h('button', { className: 'dshf-btn primary', onClick: add }, '加为好友'),
          h('button', { className: 'dshf-btn', onClick: () => { setOpen(false); setErr('') } }, '取消'),
        ),
      )
    }

    function timeAgo(sec) {
      if (sec < 0) return ''
      if (sec < 60) return '刚刚'
      if (sec < 3600) return Math.floor(sec / 60) + ' 分钟前'
      return Math.floor(sec / 3600) + ' 小时前'
    }

    function FriendRow({ fr, store, onChange }) {
      const name = fr.alias || fr.nickname || fr.code
      const status = fr.online ? fr.status : 'offline'
      const stateText = !fr.online
        ? (fr.lastSeen ? '离线 · ' + timeAgo(Math.round((Date.now() - fr.lastSeen) / 1000)) : '离线')
        : (fr.status === 'busy' && fr.label ? fr.label : STATE_TEXT[status])
      return h('div', { className: 'dshf-f' },
        h('span', { className: 'dshf-dot ' + status }),
        h('div', { className: 'dshf-f-main' },
          h('div', { className: 'dshf-f-line' },
            h('span', { style: { marginRight: 2 } }, fr.mood || '🐳'),
            h('span', { className: 'dshf-f-name' }, name),
            h('span', { className: 'dshf-f-state' }, stateText),
          ),
          fr.signature ? h('div', { className: 'dshf-f-sign' }, fr.signature) : null,
        ),
        h('div', { className: 'dshf-f-actions' },
          h('button', {
            className: 'dshf-mini', title: '戳一戳',
            disabled: !fr.online,
            onClick: () => store.poke(fr.code),
          }, '👉'),
          h('button', {
            className: 'dshf-mini', title: '删除好友',
            onClick: async () => { if (confirm('删除好友 ' + name + '？')) { await store.removeFriend(fr.code); onChange && onChange() } },
          }, '🗑'),
        ),
      )
    }

    function Panel() {
      const storeRef = React.useRef(null)
      if (!storeRef.current) storeRef.current = createStore()
      const store = storeRef.current
      const [, force] = React.useReducer((x) => x + 1, 0)
      const [editing, setEditing] = React.useState(false)
      const [failed, setFailed] = React.useState(false)

      React.useEffect(() => {
        const unsub = store.subscribe(force)
        store.init().catch(() => setFailed(true))
        return () => unsub()
      }, [])

      const s = store.state
      const friends = Array.from(s.friends.values()).sort((a, b) => {
        const rank = (f) => (f.online ? (f.status === 'busy' ? 1 : f.status === 'error' ? 2 : 0) : 9)
        const ra = rank(a), rb = rank(b)
        if (ra !== rb) return ra - rb
        return b.lastSeen - a.lastSeen
      })

      const connText = {
        connecting: '正在连接好友网络…', connected: '已连接 · 好友可实时看到你',
        reconnecting: '网络抖动，重连中…', rejected: '连接被拒，切换节点…', unsupported: '当前浏览器不支持',
      }[s.conn] || '连接中…'

      return h('div', { className: 'dshf-wrap' },
        h('div', { className: 'dshf-head' },
          h('div', { className: 'dshf-title' }, '🐳 鲸友',
            h('button', {
              className: 'dshf-mini', title: '切换中继节点', style: { marginLeft: 'auto' },
              onClick: () => store.rotateBroker(),
            }, '🔄'),
          ),
          h('div', { className: 'dshf-conn ' + (s.conn === 'connected' ? 'ok' : 'bad') }, connText),
        ),
        h(MeCard, { store, editing, setEditing }),
        h('div', { className: 'dshf-actions' },
          h('button', { className: 'dshf-btn', onClick: () => setEditing((v) => !v) }, editing ? '收起' : '✎ 编辑资料 / 签名'),
        ),
        editing ? h(EditCard, { store, onClose: () => setEditing(false) }) : null,
        h(AddRow, { store }),
        h('div', { className: 'dshf-sec' }, '好友 · ' + friends.length),
        h('div', { className: 'dshf-list' },
          friends.length === 0
            ? h('div', { className: 'dshf-empty' },
                '还没有好友。', h('br'),
                '把你的 ', bold('好友码'), ' 发给同样在用 DSH 的朋友，',
                '双方互加后就能看到对方是否在线、是不是在跑任务。',
              )
            : friends.map((fr) => h(FriendRow, { key: fr.code, fr, store, onChange: force })),
        ),
        h('div', { className: 'dshf-hint' }, '端到端加密 · 公共中继只看得到密文 · 无需注册登录'),
        // 戳一戳动画层
        ...s.pokes.map((p) => h('div', {
          key: p.key, className: 'dshf-poke',
          style: { right: 28 + Math.random() * 40, bottom: 80 + Math.random() * 120 },
          title: (p.from || '好友') + ' 戳了你',
        }, p.emoji)),
      )
    }

    // ============================================================ mount

    function apply(ctx) {
      // 样式
      ctx.effect(() => {
        const style = document.createElement('style')
        style.dataset.plugin = 'dsh-friends'
        style.textContent = CSS
        document.head.appendChild(style)
        return () => style.remove()
      }, 'dsh-friends: styles')

      try {
        if (!ctx.slots) { console.error('dsh-friends: no slots service'); return }
        ctx.slots.inject('main', () =>
          ctx.slots.inject('sidebar.panellist', () => {
            const stopMain = ctx.slots.register(
              { name: 'main', key: PANEL_ID, inject: () => ({}) },
              Panel,
            )
            const stopIcon = ctx.slots.register(
              { name: 'sidebar.panellist', id: PANEL_ID, order: 60, label: () => '鲸友' },
              FriendIcon,
            )
            return () => { try { stopIcon() } catch (e) {} try { stopMain() } catch (e) {} }
          }),
        )
      } catch (e) {
        console.error('dsh-friends: panel registration failed', e)
      }
    }

    const inject = ['slots']
    exports.apply = apply
    exports.inject = inject
    exports.name = 'dsh-friends'
    return module.exports
  },
})
