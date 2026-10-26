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
/* ============================================================
   自包含主题令牌：面板根上定义 --dshf-*，浅/深两套。
   跟随 prefers-color-scheme 与宿主 body[data-ds-dark-theme]（实测 DSH 用的就是它）。
   不猜测宿主未公开变量名——猜错会让整块配色掉回落户值，
   那正是之前「文字看不见、颜色发闷」的成因。文字一律实色，不用 opacity 调暗。
   ============================================================ */
.dshf-wrap{
  /* 深色（默认） */
  --dshf-bg:#161a21;
  --dshf-bg-2:#1d222b;
  --dshf-card:#232935;
  --dshf-card-2:#2a3140;
  --dshf-border:#333b4a;
  --dshf-border-strong:#3f4859;
  --dshf-fg:#f0f3f8;
  --dshf-fg-dim:#aab4c5;
  --dshf-fg-faint:#8792a5;
  --dshf-accent:#4d9bff;
  --dshf-accent-strong:#2f7cf6;
  --dshf-accent-soft:rgba(77,155,255,.16);
  --dshf-on-accent:#ffffff;
  --dshf-ok:#3ddc84;
  --dshf-warn:#ffb638;
  --dshf-err:#ff5f6d;
  --dshf-off:#7d8798;

  display:flex;flex-direction:column;height:100%;font-size:13px;line-height:1.45;
  color:var(--dshf-fg);background:var(--dshf-bg);
}
@media (prefers-color-scheme: light){
  .dshf-wrap{
    --dshf-bg:#ffffff;
    --dshf-bg-2:#f4f6fa;
    --dshf-card:#f2f5f9;
    --dshf-card-2:#e9eef5;
    --dshf-border:#d8dee8;
    --dshf-border-strong:#c3ccd9;
    --dshf-fg:#131720;
    --dshf-fg-dim:#4a5566;
    --dshf-fg-faint:#6b7789;
    --dshf-accent:#1f6fe0;
    --dshf-accent-strong:#155ec7;
    --dshf-accent-soft:rgba(31,111,224,.12);
    --dshf-on-accent:#ffffff;
    --dshf-ok:#12a150;
    --dshf-warn:#b97400;
    --dshf-err:#d63a48;
    --dshf-off:#8b95a5;
  }
}
/* 宿主深色主题下给 body 打这个属性（实测），覆盖系统偏好 */
body[data-ds-dark-theme] .dshf-wrap{
  --dshf-bg:#161a21;--dshf-bg-2:#1d222b;--dshf-card:#232935;--dshf-card-2:#2a3140;
  --dshf-border:#333b4a;--dshf-border-strong:#3f4859;--dshf-fg:#f0f3f8;
  --dshf-fg-dim:#aab4c5;--dshf-fg-faint:#8792a5;--dshf-accent:#4d9bff;
  --dshf-accent-strong:#2f7cf6;--dshf-accent-soft:rgba(77,155,255,.16);
  --dshf-ok:#3ddc84;--dshf-warn:#ffb638;--dshf-err:#ff5f6d;--dshf-off:#7d8798;
}

/* ---------- 头部 ---------- */
.dshf-head{padding:14px 14px 10px}
.dshf-title{display:flex;align-items:center;gap:8px;font-weight:650;font-size:15px;color:var(--dshf-fg)}
.dshf-title .dshf-mini{margin-left:auto}
.dshf-conn{font-size:11.5px;margin-top:3px;color:var(--dshf-fg-dim);display:flex;align-items:center;gap:5px}
.dshf-conn::before{content:'';width:6px;height:6px;border-radius:50%;background:var(--dshf-fg-faint);flex:0 0 auto}
.dshf-conn.ok{color:var(--dshf-ok)}
.dshf-conn.ok::before{background:var(--dshf-ok)}
.dshf-conn.bad{color:var(--dshf-warn)}
.dshf-conn.bad::before{background:var(--dshf-warn)}

/* ---------- 我的卡片 ---------- */
.dshf-me{margin:2px 12px 10px;padding:12px;border-radius:14px;background:var(--dshf-card);border:1px solid var(--dshf-border)}
.dshf-me-row{display:flex;align-items:center;gap:9px}
.dshf-mood{font-size:22px;line-height:1;flex:0 0 auto}
.dshf-nick{font-weight:650;font-size:14px;color:var(--dshf-fg);white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.dshf-sign{margin-top:9px;font-size:12.5px;color:var(--dshf-fg);line-height:1.5;word-break:break-word}
.dshf-task{margin-top:10px;display:flex;align-items:center;gap:7px}
.dshf-task-badge{display:inline-flex;align-items:center;gap:6px;padding:3px 9px;border-radius:999px;font-size:11.5px;font-weight:600;color:var(--dshf-fg);background:var(--dshf-card-2);border:1px solid var(--dshf-border)}
.dshf-task-badge::before{content:'';width:7px;height:7px;border-radius:50%;background:var(--dshf-ok);flex:0 0 auto}
.dshf-task-badge.busy::before{background:var(--dshf-warn)}
.dshf-task-badge.error::before{background:var(--dshf-err)}
.dshf-task-label{font-size:11.5px;color:var(--dshf-fg-dim);white-space:nowrap;overflow:hidden;text-overflow:ellipsis}

/* 好友码：独立一行 + 标签 + 大号等宽字 + 复制按钮 */
.dshf-code-row{margin-top:12px;padding-top:11px;border-top:1px dashed var(--dshf-border);display:flex;align-items:center;gap:9px;flex-wrap:wrap}
.dshf-code-label{font-size:11px;color:var(--dshf-fg-dim);letter-spacing:.03em;flex:0 0 auto}
.dshf-code-value{font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;font-size:18px;font-weight:700;letter-spacing:.16em;color:var(--dshf-accent);background:var(--dshf-accent-soft);border:1px solid var(--dshf-accent);border-radius:9px;padding:4px 11px;user-select:all;cursor:pointer}
.dshf-code-copy{font-size:11.5px;padding:4px 9px;border-radius:8px;border:1px solid var(--dshf-border-strong);background:transparent;color:var(--dshf-fg-dim);cursor:pointer;margin-left:auto;flex:0 0 auto}
.dshf-code-copy:hover{background:var(--dshf-card-2);color:var(--dshf-fg)}

/* ---------- 操作区 ---------- */
.dshf-actions{display:flex;gap:7px;margin:0 12px 10px;flex-wrap:wrap}
.dshf-btn{font-size:12.5px;font-weight:550;padding:6px 11px;border-radius:9px;border:1px solid var(--dshf-border-strong);background:var(--dshf-card);color:var(--dshf-fg);cursor:pointer}
.dshf-btn:hover{background:var(--dshf-card-2);border-color:var(--dshf-accent)}
.dshf-btn.primary{background:var(--dshf-accent-strong);border-color:var(--dshf-accent-strong);color:var(--dshf-on-accent)}
.dshf-btn.primary:hover{filter:brightness(1.08)}
.dshf-btn:disabled{opacity:.55;cursor:default}

/* ---------- 表单 ---------- */
.dshf-edit{margin:0 12px 10px;padding:12px;background:var(--dshf-card);border:1px solid var(--dshf-border);border-radius:12px}
.dshf-edit .dshf-input{margin-bottom:8px;width:100%;box-sizing:border-box}
.dshf-field-label{font-size:11px;color:var(--dshf-fg-dim);margin:0 0 3px 2px}
.dshf-inputrow{display:flex;gap:6px;margin:0 12px 10px}
.dshf-input{flex:1;min-width:0;font:inherit;font-size:12.5px;padding:7px 10px;border-radius:9px;border:1px solid var(--dshf-border-strong);background:var(--dshf-bg-2);color:var(--dshf-fg)}
.dshf-input::placeholder{color:var(--dshf-fg-faint)}
.dshf-input:focus{outline:none;border-color:var(--dshf-accent)}
.dshf-err-text{color:var(--dshf-err);font-size:11.5px;margin-bottom:8px}

/* ---------- 好友列表 ---------- */
.dshf-sec{padding:4px 14px 6px;font-size:11px;font-weight:650;letter-spacing:.06em;color:var(--dshf-fg-faint);text-transform:uppercase}
.dshf-list{flex:1;overflow:auto;margin:0 8px 12px;padding:0 4px}
.dshf-f{display:flex;align-items:flex-start;gap:10px;padding:10px 9px;border-radius:12px;border:1px solid transparent}
.dshf-f:hover{background:var(--dshf-card);border-color:var(--dshf-border)}
.dshf-dot{width:9px;height:9px;border-radius:50%;margin-top:6px;flex:0 0 auto}
.dshf-dot.online{background:var(--dshf-ok)}
.dshf-dot.busy{background:var(--dshf-warn)}
.dshf-dot.error{background:var(--dshf-err)}
.dshf-dot.offline{background:var(--dshf-off)}
.dshf-f-main{min-width:0;flex:1}
.dshf-f-line{display:flex;align-items:baseline;gap:7px}
.dshf-f-name{font-weight:600;font-size:13px;color:var(--dshf-fg);white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.dshf-f-state{font-size:11.5px;color:var(--dshf-fg-dim);white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.dshf-f-sign{font-size:11.5px;color:var(--dshf-fg-dim);margin-top:3px;line-height:1.4;word-break:break-word;display:-webkit-box;-webkit-line-clamp:2;-webkit-box-orient:vertical;overflow:hidden}
.dshf-f-actions{display:flex;gap:4px;opacity:0;transition:opacity .12s;flex:0 0 auto}
.dshf-f:hover .dshf-f-actions,.dshf-f:focus-within .dshf-f-actions{opacity:1}
.dshf-mini{font-size:14px;width:26px;height:26px;border-radius:8px;cursor:pointer;border:1px solid var(--dshf-border);background:var(--dshf-card-2);color:var(--dshf-fg-dim);display:inline-flex;align-items:center;justify-content:center;padding:0}
.dshf-mini:hover{background:var(--dshf-bg-2);color:var(--dshf-fg);border-color:var(--dshf-accent)}
.dshf-mini:disabled{opacity:.4;cursor:default}
.dshf-rename{width:100%;box-sizing:border-box;padding:3px 8px;font-size:12.5px;font-weight:600}

.dshf-empty{padding:30px 20px;text-align:center;color:var(--dshf-fg-dim);line-height:1.7;font-size:12.5px}
.dshf-empty b{color:var(--dshf-fg);font-weight:650}
.dshf-empty-code{display:inline-block;margin-top:10px;font-family:ui-monospace,Menlo,Consolas,monospace;font-size:16px;font-weight:700;letter-spacing:.16em;color:var(--dshf-accent);background:var(--dshf-accent-soft);border:1px solid var(--dshf-accent);border-radius:9px;padding:5px 11px;cursor:pointer;user-select:all}

/* ---------- 好友申请 ---------- */
.dshf-badge{display:inline-flex;align-items:center;justify-content:center;min-width:17px;height:17px;padding:0 5px;border-radius:999px;background:var(--dshf-err);color:#fff;font-size:10.5px;font-weight:700;line-height:1}
.dshf-reqs{margin:0 8px 6px}
.dshf-req{display:flex;align-items:flex-start;gap:9px;padding:10px;margin:0 0 6px;border-radius:12px;background:var(--dshf-card);border:1px solid var(--dshf-accent)}
.dshf-req-main{min-width:0;flex:1}
.dshf-req-line{display:flex;align-items:baseline;gap:7px}
.dshf-req-name{font-weight:600;font-size:13px;color:var(--dshf-fg);white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.dshf-req-code{font-family:ui-monospace,Menlo,Consolas,monospace;font-size:11.5px;color:var(--dshf-accent);letter-spacing:.08em}
.dshf-req-state{font-size:11.5px;color:var(--dshf-warn)}
.dshf-req-msg{font-size:11.5px;color:var(--dshf-fg-dim);margin-top:3px;line-height:1.4;word-break:break-word}
.dshf-req-time{font-size:10.5px;color:var(--dshf-fg-faint);margin-top:3px}
.dshf-req-actions{display:flex;gap:5px;flex:0 0 auto}

/* ---------- 设置 ---------- */
.dshf-segrow{display:flex;gap:0;margin:0 0 6px;border:1px solid var(--dshf-border-strong);border-radius:9px;overflow:hidden}
.dshf-seg{flex:1;font:inherit;font-size:12px;padding:6px 8px;border:none;background:var(--dshf-bg-2);color:var(--dshf-fg-dim);cursor:pointer}
.dshf-seg + .dshf-seg{border-left:1px solid var(--dshf-border-strong)}
.dshf-seg.on{background:var(--dshf-accent-strong);color:var(--dshf-on-accent);font-weight:600}
.dshf-seg:hover:not(.on){background:var(--dshf-card-2);color:var(--dshf-fg)}
.dshf-linkrow{display:flex;gap:6px;align-items:center;margin-bottom:4px}
.dshf-linkrow .dshf-input{font-size:11.5px}
.dshf-mode-note{font-size:11px;color:var(--dshf-fg-dim);line-height:1.5;margin:2px 0 10px;padding:7px 9px;background:var(--dshf-bg-2);border-radius:8px;border-left:2px solid var(--dshf-accent)}
.dshf-hint-inline{font-size:11.5px;color:var(--dshf-ok);margin:0 0 8px 2px}
.dshf-ok-text{color:var(--dshf-ok);font-size:11.5px;margin-bottom:8px;line-height:1.4}
.dshf-toast{position:fixed;left:50%;bottom:96px;transform:translateX(-50%);z-index:9998;max-width:280px;padding:8px 13px;border-radius:10px;background:var(--dshf-accent-strong);color:#fff;font-size:12px;font-weight:550;box-shadow:0 6px 20px rgba(0,0,0,.28);animation:dshf-toast-in .18s ease-out}
@keyframes dshf-toast-in{from{opacity:0;transform:translateX(-50%) translateY(8px)}to{opacity:1;transform:translateX(-50%) translateY(0)}}

.dshf-hint{font-size:11px;color:var(--dshf-fg-faint);padding:0 14px 14px;line-height:1.5}

/* ---------- 戳一戳 ---------- */
.dshf-poke{position:fixed;font-size:26px;pointer-events:none;z-index:9999;animation:dshf-float 1.6s ease-out forwards}
@keyframes dshf-float{0%{opacity:0;transform:translateY(8px) scale(.6)}18%{opacity:1;transform:translateY(0) scale(1.15)}100%{opacity:0;transform:translateY(-64px) scale(1)}}
`
    // ============================================================ presence store

    // 一个好友 = 一个好友码。在线状态来自 presence 心跳；戳一戳是即时事件。
    function createStore() {
      const listeners = new Set()
      const state = {
        me: null, // {id,nickname,signature,mood,code,friends,acceptMode,stealth,requests,task}
        friends: new Map(), // code -> {code,alias,online,status,label,nickname,signature,mood,lastSeen,idleSec,addedAt}
        conn: 'connecting', // connecting|connected|reconnecting|rejected|unsupported
        brokerIdx: 0,
        pokes: [], // 收到的戳一戳动画 {key,emoji}
        toasts: [], // 轻提示 {key,text}
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
        // 隐身：完全不广播，好友侧 3 个心跳后自然显示离线
        if (state.me.stealth === true) return
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
          await sendTo(f.code, msg)
        }
      }

      async function sendBye() {
        if (!mqtt || !state.me) return
        for (const f of state.me.friends) {
          try { mqtt.publish(topicFor(f.code), new TextEncoder().encode(await seal({ kind: 'bye', id: state.me.id, ts: Date.now() }, f.code))) } catch (e) {}
        }
      }

      /**
       * 所有可能收到消息的码：好友 + 待处理的申请方 + 我发出申请的对方。
       * 好友申请阶段对方还不是好友，所以必须把请求相关的码也加进来，否则解不开。
       */
      function candidateCodes() {
        const me = state.me
        if (!me) return []
        const codes = new Set()
        for (const f of me.friends) codes.add(f.code)
        for (const r of (me.requests.incoming || [])) codes.add(r.code)
        for (const r of (me.requests.outgoing || [])) codes.add(r.code)
        return Array.from(codes)
      }

      async function handleMessage(topic, payloadBytes) {
        if (!state.me) return
        const text = new TextDecoder().decode(payloadBytes)
        // 逐个候选码尝试解密；一份密文只可能被一个码解开
        for (const code of candidateCodes()) {
          const msg = await open(text, code)
          if (!msg) continue
          const friend = state.friends.get(code)
          const isFriend = friend !== undefined
          const me = state.me

          if (msg.kind === 'presence' && isFriend) {
            friend.online = true
            friend.status = msg.status === 'busy' ? 'busy' : msg.status === 'error' ? 'error' : 'online'
            friend.label = msg.label || ''
            friend.nickname = msg.nickname || friend.nickname
            friend.signature = msg.signature || ''
            friend.mood = msg.mood || '🐳'
            friend.id = msg.id
            friend.lastSeen = Date.now()
            emit()
          } else if (msg.kind === 'bye' && isFriend) {
            friend.online = false; friend.status = 'offline'; friend.lastSeen = Date.now(); emit()
          } else if (msg.kind === 'poke' && isFriend) {
            friend.online = true; friend.lastSeen = Date.now()
            const key = Math.random().toString(36).slice(2)
            state.pokes.push({ key, emoji: msg.emoji || '👉', from: friend.alias || friend.nickname || code })
            emit()
            setTimeout(() => { state.pokes = state.pokes.filter((p) => p.key !== key); emit() }, 1700)

          // ---------- 好友申请流程 ----------
          } else if (msg.kind === 'friend_request') {
            // 别人加我：若已是好友则忽略；若开着 auto 就直接同意并回执
            if (me.friends.some((f) => f.code === code)) return
            const inc = (me.requests.incoming || []).slice()
            if (!inc.some((r) => r.code === code)) {
              inc.push({
                code,
                fromNickname: msg.fromNickname || '',
                message: msg.message || '',
                ts: msg.ts || Date.now(),
              })
              await apiPost('/profile', { requests: { incoming: inc, outgoing: me.requests.outgoing || [] } })
              await refreshMe()
            }
            if (me.acceptMode === 'auto') {
              await acceptRequest(code)
            }
            return
          } else if (msg.kind === 'friend_accept') {
            // 我加的人同意了：互相成为好友，清掉我的 outgoing 记录
            const friends = me.friends.slice()
            const out = (me.requests.outgoing || []).filter((r) => r.code !== code)
            if (!friends.some((f) => f.code === code)) {
              friends.push({ code, alias: msg.nickname || '', addedAt: Date.now() })
              await apiPost('/friends', { friends })
            }
            await apiPost('/profile', { requests: { incoming: me.requests.incoming || [], outgoing: out } })
            await refreshMe()
            // 面板上给个 toast：用戳一戳的动画位提示一下
            state.toasts = state.toasts || []
            const tk = Math.random().toString(36).slice(2)
            state.toasts.push({ key: tk, text: (msg.nickname || code) + ' 同意了你的好友请求' })
            emit()
            setTimeout(() => { state.toasts = (state.toasts || []).filter((t) => t.key !== tk); emit() }, 2600)
            return
          } else if (msg.kind === 'friend_remove' && isFriend) {
            // 对方删了我：本地也删掉，并清掉相关请求
            const friends = me.friends.filter((f) => f.code !== code)
            await apiPost('/friends', { friends })
            state.friends.delete(code)
            await apiPost('/profile', {
              requests: {
                incoming: (me.requests.incoming || []).filter((r) => r.code !== code),
                outgoing: (me.requests.outgoing || []).filter((r) => r.code !== code),
              },
            })
            await refreshMe()
            return
          }
          return // 一份密文只可能被一个码解开
        }
      }

      /**
       * 加好友：按「需要同意」模式发申请。
       * 对方若开着 auto（无需同意），会直接回 accept，双方立刻成为好友。
       */
      async function addFriend(code, alias, message) {
        code = String(code).toUpperCase()
        if (!validCode(code)) throw new Error('好友码应为 6 位字母数字')
        if (state.me && code === state.me.code) throw new Error('不能加自己为好友')
        const friends = (state.me ? state.me.friends : []).slice()
        if (friends.some((f) => f.code === code)) throw new Error('已经是好友了')
        const out = (state.me.requests ? state.me.requests.outgoing : []).slice()
        if (out.some((r) => r.code === code)) throw new Error('已经发过申请了，等对方回应')

        // 先落一条「已发出」，再发加密申请
        const entry = { code, fromNickname: state.me.nickname, message: (message || '').slice(0, 60), ts: Date.now() }
        out.push(entry)
        await apiPost('/profile', { requests: { incoming: state.me.requests.incoming, outgoing: out } })
        await refreshMe()
        await sendTo(code, {
          kind: 'friend_request',
          from: state.me.id,
          fromNickname: state.me.nickname,
          message: entry.message,
          ts: entry.ts,
        })
        return 'sent'
      }

      /** 同意一条好友申请：互加为好友，并清掉双方的申请记录。 */
      async function acceptRequest(code) {
        code = String(code).toUpperCase()
        const me = state.me
        const req = (me.requests.incoming || []).find((r) => r.code === code)
        if (!req) throw new Error('没有这条申请')

        // 1) 加对方为好友（沿用对方在申请里给的昵称做初始备注）
        const friends = me.friends.slice()
        if (!friends.some((f) => f.code === code)) {
          friends.push({ code, alias: req.fromNickname || '', addedAt: Date.now() })
        }
        // 2) 清掉 incoming 里这条 + 清掉 outgoing 里可能存在的反向申请
        const incoming = me.requests.incoming.filter((r) => r.code !== code)
        const outgoing = me.requests.outgoing.filter((r) => r.code !== code)
        await apiPost('/friends', { friends })
        await apiPost('/profile', { requests: { incoming, outgoing } })
        await refreshMe()
        // 3) 告诉对方「我同意了」
        await sendTo(code, {
          kind: 'friend_accept',
          from: me.id,
          nickname: me.nickname,
          ts: Date.now(),
        })
        sendPresence()
        return 'accepted'
      }

      /** 拒绝一条好友申请（只删本地记录，不通知对方）。 */
      async function rejectRequest(code) {
        code = String(code).toUpperCase()
        const me = state.me
        const incoming = (me.requests.incoming || []).filter((r) => r.code !== code)
        await apiPost('/profile', { requests: { incoming, outgoing: me.requests.outgoing || [] } })
        await refreshMe()
        return 'rejected'
      }

      /** 撤回一条我发出的申请。 */
      async function cancelRequest(code) {
        code = String(code).toUpperCase()
        const me = state.me
        const outgoing = (me.requests.outgoing || []).filter((r) => r.code !== code)
        await apiPost('/profile', { requests: { incoming: me.requests.incoming || [], outgoing } })
        await refreshMe()
        return 'cancelled'
      }

      /** 删好友：本地删除 + 通知对方。 */
      async function removeFriend(code) {
        code = String(code).toUpperCase()
        const me = state.me
        const friends = me.friends.filter((f) => f.code !== code)
        await apiPost('/friends', { friends })
        state.friends.delete(code)
        await refreshMe()
        await sendTo(code, { kind: 'friend_remove', from: me.id, ts: Date.now() })
        sendPresence()
      }

      /** 更新某个好友的备注名。 */
      async function setAlias(code, alias) {
        code = String(code).toUpperCase()
        const friends = state.me.friends.map((f) => (f.code === code ? { ...f, alias: String(alias || '').slice(0, 24) } : f))
        await apiPost('/friends', { friends })
        await refreshMe()
      }

      /** 加密发送一条协议消息给指定好友码。 */
      async function sendTo(code, obj) {
        if (!mqtt || !state.me) return false
        try {
          const sealed = await seal(obj, code)
          return mqtt.publish(topicFor(code), new TextEncoder().encode(sealed))
        } catch (e) {
          return false
        }
      }

      /** 生成邀请链接（含好友码），朋友粘贴即可添加。 */
      function inviteLink() {
        return 'dsh-friends://add?code=' + state.me.code
      }

      async function poke(code) {
        if (!mqtt || !state.me) return
        const emojis = ['👉', '🐟', '💧', '❤️', '🫧', '⚡']
        const emoji = emojis[Math.floor(Math.random() * emojis.length)]
        await sendTo(code, { kind: 'poke', from: state.me.id, emoji, ts: Date.now() })
        return emoji
      }

      async function updateProfile(patch) {
        const saved = await apiPost('/profile', patch)
        await refreshMe()
        sendPresence()
        return saved
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
        updateProfile, addFriend, removeFriend, poke, setAlias,
        acceptRequest, rejectRequest, cancelRequest, inviteLink,
        rotateBroker() {
          // 手动换节点：排除当前正在用的那个，逼探测挑另一个。
          const current = mqtt && mqtt.currentUrl ? mqtt.currentUrl() : undefined
          state.brokerIdx++
          startRelay(current)
        },
      }
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
        h('path', { d: 'M40 14c8 0 14 6 14 13 0 6-4 10-9 11l3 5-6-3c-1 0-2 .5-3 .5-3 0-6-1-8-3l4-3c2 1 4 2 6 2 5 0 8-3 8-7s-4-7-9-7c-4 0-7 2-8 5l-5-1c2-7 8-9 13-9Z', fill: 'currentColor', opacity: '0.5' }),
        h('path', { d: 'M12 30c0-9 8-16 19-16 9 0 17 6 17 14 0 8-7 14-17 14-2 0-4-.3-6-.8l-7 4 2-7c-5-2-8-6-8-8Z', fill: 'currentColor' }),
        h('circle', { cx: '38', cy: '28', r: '2.2', fill: 'var(--dshf-bg,#161a21)' }),
        h('circle', { cx: '20', cy: '12', r: '4.5', fill: '#3ddc84' }),
      )
    }

    function copyText(t) {
      try {
        if (navigator.clipboard && navigator.clipboard.writeText) navigator.clipboard.writeText(t)
      } catch (e) { /* ignore */ }
    }

    /** 复制后给一句反馈（clipboard 在部分上下文里不可用）。 */
    function CopyButton({ value, className, children }) {
      const [done, setDone] = React.useState(false)
      return h('button', {
        className,
        onClick: () => {
          copyText(value)
          setDone(true)
          setTimeout(() => setDone(false), 1400)
        },
      }, done ? '已复制 ✓' : children)
    }

    function MeCard({ store, editing, setEditing }) {
      const me = store.state.me
      if (!me) return h('div', { className: 'dshf-me' }, '正在读取资料…')
      const t = me.task && me.task.active
      const taskKind = t ? (me.task.error ? 'error' : 'busy') : 'idle'
      const taskText = t ? (me.task.label || (me.task.error ? '遇到问题，等人处理' : '执行任务中')) : '在线空闲'
      return h('div', { className: 'dshf-me' },
        h('div', { className: 'dshf-me-row' },
          h('span', { className: 'dshf-mood' }, me.mood || '🐳'),
          h('span', { className: 'dshf-nick' }, me.nickname),
        ),
        h('div', { className: 'dshf-sign' }, me.signature),
        h('div', { className: 'dshf-task' },
          h('span', { className: 'dshf-task-badge ' + (taskKind === 'idle' ? '' : taskKind) }, taskText),
          taskKind !== 'idle' ? h('span', { className: 'dshf-task-label' }, '好友可见') : null,
        ),
        // 好友码单独一行：标签 + 大号等宽 + 复制按钮，不再是被忽略的小徽章
        h('div', { className: 'dshf-code-row' },
          h('span', { className: 'dshf-code-label' }, '我的好友码'),
          h('span', {
            className: 'dshf-code-value', title: '点击复制',
            onClick: () => copyText(me.code),
          }, me.code),
          h(CopyButton, { value: me.code, className: 'dshf-code-copy' }, '复制'),
        ),
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
        h('div', { className: 'dshf-field-label' }, '昵称'),
        h('input', { className: 'dshf-input', value: nick, maxLength: 24, placeholder: '昵称', onChange: (e) => setNick(e.target.value) }),
        h('div', { className: 'dshf-field-label' }, '心情 emoji'),
        h('input', { className: 'dshf-input', value: mood, maxLength: 4, placeholder: '🐳', onChange: (e) => setMood(e.target.value) }),
        h('div', { className: 'dshf-field-label' }, '个性签名（60 字内，有趣一点）'),
        h('input', { className: 'dshf-input', value: sign, maxLength: 60, placeholder: '例如：今天我的 AI 又把 rm -rf 写对了', onChange: (e) => setSign(e.target.value) }),
        err ? h('div', { className: 'dshf-err-text' }, err) : null,
        h('div', { style: { display: 'flex', gap: 7 } },
          h('button', { className: 'dshf-btn primary', disabled: busy, onClick: save }, busy ? '保存中…' : '保存'),
          h('button', { className: 'dshf-btn', onClick: onClose }, '取消'),
        ),
      )
    }

    /**
     * 从任意粘贴内容里提取 6 位好友码：
     * 支持 `dsh-friends://add?code=K7M2QX`、`https://...?code=K7M2QX`、
     * 或干脆就是 `K7M2QX`。提取不到返回 null。
     */
    function extractCode(raw) {
      const s = String(raw || '').trim()
      if (s === '') return null
      const m = /[?&]code=([A-Za-z0-9]{6})/.exec(s)
      if (m) return m[1].toUpperCase()
      const bare = /^\s*([A-Za-z0-9]{6})\s*$/.exec(s)
      if (bare) return bare[1].toUpperCase()
      return null
    }

    function AddRow({ store }) {
      const [raw, setRaw] = React.useState('')
      const [alias, setAlias] = React.useState('')
      const [message, setMessage] = React.useState('')
      const [open, setOpen] = React.useState(false)
      const [err, setErr] = React.useState('')
      const [sent, setSent] = React.useState('')
      const me = store.state.me
      const autoMode = me && me.acceptMode === 'auto'
      const code = extractCode(raw)

      if (!open) return h('div', { className: 'dshf-actions' },
        h('button', { className: 'dshf-btn primary', onClick: () => { setOpen(true); setSent('') } }, '＋ 添加好友'),
      )

      async function add() {
        setErr(''); setSent('')
        try {
          const result = await store.addFriend(raw, alias, message)
          if (result === 'sent') {
            // 留着表单但提示已发出，用户能继续加下一个人
            setSent('申请已发出，等对方同意后就会出现在好友列表。')
            setRaw(''); setAlias(''); setMessage('')
          }
        } catch (e) { setErr(e.message || String(e)) }
      }

      return h('div', { className: 'dshf-edit' },
        h('div', { className: 'dshf-field-label' }, '对方的好友码或邀请链接'),
        h('input', {
          className: 'dshf-input', value: raw, maxLength: 200,
          placeholder: '粘贴 dsh-friends://add?code=… 或直接输 6 位码',
          onChange: (e) => setRaw(e.target.value),
        }),
        code ? h('div', { className: 'dshf-hint-inline' }, '识别到好友码：' + code) : null,
        h('div', { className: 'dshf-field-label' }, '备注名（可选）'),
        h('input', { className: 'dshf-input', value: alias, maxLength: 24, placeholder: '备注名', onChange: (e) => setAlias(e.target.value) }),
        h('div', { className: 'dshf-field-label' }, '申请留言（可选，60 字内）'),
        h('input', { className: 'dshf-input', value: message, maxLength: 60, placeholder: '例如：我是老王，加个鲸友', onChange: (e) => setMessage(e.target.value) }),
        h('div', { className: 'dshf-mode-note' }, autoMode
          ? '你开启了「无需同意」：别人加你会直接通过；你加别人时，对方若也需要同意，仍要等对方点同意。'
          : '当前是「需要同意」模式：对方会收到你的申请，同意后才成为好友。'),
        err ? h('div', { className: 'dshf-err-text' }, err) : null,
        sent ? h('div', { className: 'dshf-ok-text' }, sent) : null,
        h('div', { style: { display: 'flex', gap: 7 } },
          h('button', { className: 'dshf-btn primary', disabled: !code, onClick: add }, '发送申请'),
          h('button', { className: 'dshf-btn', onClick: () => { setOpen(false); setErr(''); setSent('') } }, '取消'),
        ),
      )
    }

    /** 一条待处理的好友申请（别人加我）。 */
    function IncomingRow({ req, store, onChange }) {
      const [busy, setBusy] = React.useState(false)
      async function act(fn) {
        setBusy(true)
        try { await fn() } catch (e) { /* 忽略，面板会刷新 */ }
        setBusy(false)
        onChange && onChange()
      }
      return h('div', { className: 'dshf-req' },
        h('div', { className: 'dshf-req-main' },
          h('div', { className: 'dshf-req-line' },
            h('span', { className: 'dshf-req-name' }, req.fromNickname || req.code),
            h('span', { className: 'dshf-req-code' }, req.code),
          ),
          req.message ? h('div', { className: 'dshf-req-msg' }, '“' + req.message + '”') : null,
          h('div', { className: 'dshf-req-time' }, timeAgo(Math.round((Date.now() - (req.ts || Date.now())) / 1000)) + '前'),
        ),
        h('div', { className: 'dshf-req-actions' },
          h('button', {
            className: 'dshf-btn primary', disabled: busy,
            onClick: () => act(() => store.acceptRequest(req.code)),
          }, '同意'),
          h('button', {
            className: 'dshf-btn', disabled: busy,
            onClick: () => act(() => store.rejectRequest(req.code)),
          }, '拒绝'),
        ),
      )
    }

    /** 一条我发出的申请（等对方回应）。 */
    function OutgoingRow({ req, store, onChange }) {
      const [busy, setBusy] = React.useState(false)
      return h('div', { className: 'dshf-req' },
        h('div', { className: 'dshf-req-main' },
          h('div', { className: 'dshf-req-line' },
            h('span', { className: 'dshf-req-name' }, req.code),
            h('span', { className: 'dshf-req-state' }, '等待对方回应'),
          ),
          req.message ? h('div', { className: 'dshf-req-msg' }, '“' + req.message + '”') : null,
        ),
        h('div', { className: 'dshf-req-actions' },
          h('button', {
            className: 'dshf-btn', disabled: busy,
            onClick: async () => { setBusy(true); try { await store.cancelRequest(req.code) } catch (e) {} setBusy(false); onChange && onChange() },
          }, '撤回'),
        ),
      )
    }

    /** 好友请求区（有待处理申请时才显示）。 */
    function RequestsCard({ store }) {
      const me = store.state.me
      const [, force] = React.useReducer((x) => x + 1, 0)
      const inc = (me && me.requests.incoming) || []
      const out = (me && me.requests.outgoing) || []
      if (inc.length === 0 && out.length === 0) return null
      return h('div', { className: 'dshf-reqs' },
        inc.length > 0 ? h('div', { className: 'dshf-sec' }, '好友请求 · ' + inc.length) : null,
        ...inc.map((r) => h(IncomingRow, { key: 'i' + r.code, req: r, store, onChange: force })),
        out.length > 0 ? h('div', { className: 'dshf-sec' }, '已发出的申请 · ' + out.length) : null,
        ...out.map((r) => h(OutgoingRow, { key: 'o' + r.code, req: r, store, onChange: force })),
      )
    }

    /** 加好友设置：同意模式 / 隐身 / 邀请链接。 */
    function SettingsCard({ store, onClose }) {
      const me = store.state.me
      const [busy, setBusy] = React.useState(false)
      const [linkCopied, setLinkCopied] = React.useState(false)
      async function patch(p) {
        setBusy(true)
        try { await store.updateProfile(p) } catch (e) { /* ignore */ }
        setBusy(false)
      }
      return h('div', { className: 'dshf-edit' },
        h('div', { className: 'dshf-field-label' }, '别人加我时'),
        h('div', { className: 'dshf-segrow' },
          h('button', {
            className: 'dshf-seg' + (me.acceptMode === 'approve' ? ' on' : ''),
            disabled: busy, onClick: () => patch({ acceptMode: 'approve' }),
          }, '需要我同意'),
          h('button', {
            className: 'dshf-seg' + (me.acceptMode === 'auto' ? ' on' : ''),
            disabled: busy, onClick: () => patch({ acceptMode: 'auto' }),
          }, '无需同意，直接通过'),
        ),
        h('div', { className: 'dshf-mode-note' }, me.acceptMode === 'auto'
          ? '任何人输入你的好友码都会立刻成为好友，你会收到一条通知。适合公开分享码的场景。'
          : '别人加你需要你点「同意」。推荐默认，避免陌生人直接进来。'),
        h('div', { className: 'dshf-field-label' }, '隐身模式'),
        h('div', { className: 'dshf-segrow' },
          h('button', {
            className: 'dshf-seg' + (me.stealth ? ' on' : ''),
            disabled: busy, onClick: () => patch({ stealth: !me.stealth }),
          }, me.stealth ? '已开启：好友看到你离线' : '已关闭：好友看到你在线'),
        ),
        h('div', { className: 'dshf-field-label' }, '邀请链接'),
        h('div', { className: 'dshf-linkrow' },
          h('input', { className: 'dshf-input', value: store.inviteLink(), readOnly: true, onFocus: (e) => e.target.select() }),
          h('button', {
            className: 'dshf-btn',
            onClick: () => { copyText(store.inviteLink()); setLinkCopied(true); setTimeout(() => setLinkCopied(false), 1500) },
          }, linkCopied ? '已复制 ✓' : '复制'),
        ),
        h('div', { className: 'dshf-mode-note' }, '把链接发给朋友，他粘贴到添加框就会自动识别你的好友码。'),
        h('div', { style: { display: 'flex', gap: 7, marginTop: 4 } },
          h('button', { className: 'dshf-btn', onClick: onClose }, '完成'),
        ),
      )
    }

    function timeAgo(sec) {
      if (sec < 0) return ''
      if (sec < 60) return '刚刚'
      if (sec < 3600) return Math.floor(sec / 60) + ' 分钟'
      return Math.floor(sec / 3600) + ' 小时'
    }

    /** 小图标按钮用的内联 SVG（不依赖 emoji 字体，随主题反色）。 */
    function MiniIcon({ path, size }) {
      return h('svg', {
        width: size || 15, height: size || 15, viewBox: '0 0 20 20', fill: 'none',
        stroke: 'currentColor', strokeWidth: 1.6, strokeLinecap: 'round', strokeLinejoin: 'round',
        'aria-hidden': 'true', focusable: 'false',
      }, h('path', { d: path }))
    }
    const ICON_POKE = 'M7 11V6.5a1.5 1.5 0 0 1 3 0V11m0-1.5V5a1.5 1.5 0 0 1 3 0v6m0-1a1.5 1.5 0 0 1 3 0v2.5a5 5 0 0 1-5 5h-1a5 5 0 0 1-5-5v-2.2a1.5 1.5 0 0 1 3 0'
    const ICON_TRASH = 'M4.5 6.5h11M8 6.5V5a1 1 0 0 1 1-1h2a1 1 0 0 1 1 1v1.5M6.5 6.5l.6 9a1 1 0 0 0 1 1h3.8a1 1 0 0 0 1-1l.6-9M9 9.5v4M11 9.5v4'

    const ICON_PENCIL = 'M13.2 4.6l2.2 2.2-7.4 7.4-3 .6.6-3 7.6-7.2Zm0-1.1l1.4-1.4a1 1 0 0 1 1.4 0l2.9 2.9a1 1 0 0 1 0 1.4L17 8.2 13.2 3.5Z'

    function FriendRow({ fr, store, onChange }) {
      const name = fr.alias || fr.nickname || fr.code
      const status = fr.online ? fr.status : 'offline'
      const stateText = !fr.online
        ? (fr.lastSeen ? '离线 · ' + timeAgo(Math.round((Date.now() - fr.lastSeen) / 1000)) : '离线')
        : ((fr.status === 'busy' || fr.status === 'error') && fr.label ? fr.label : STATE_TEXT[status])
      // 备注名内联编辑：点铅笔变成输入框，回车/失焦保存
      const [renaming, setRenaming] = React.useState(false)
      const [draft, setDraft] = React.useState(fr.alias || '')
      async function save() {
        setRenaming(false)
        const next = draft.trim()
        if (next !== (fr.alias || '')) {
          try { await store.setAlias(fr.code, next) } catch (e) { /* ignore */ }
          onChange && onChange()
        }
      }
      return h('div', { className: 'dshf-f' },
        h('span', { className: 'dshf-dot ' + status }),
        h('div', { className: 'dshf-f-main' },
          renaming
            ? h('input', {
                className: 'dshf-input dshf-rename', value: draft, maxLength: 24, autoFocus: true,
                placeholder: '备注名', onChange: (e) => setDraft(e.target.value),
                onBlur: save,
                onKeyDown: (e) => { if (e.key === 'Enter') save(); if (e.key === 'Escape') { setDraft(fr.alias || ''); setRenaming(false) } },
              })
            : h('div', { className: 'dshf-f-line' },
                h('span', { style: { marginRight: 2, flex: '0 0 auto' } }, fr.mood || '🐳'),
                h('span', { className: 'dshf-f-name' }, name),
                h('span', { className: 'dshf-f-state' }, stateText),
              ),
          fr.signature ? h('div', { className: 'dshf-f-sign' }, fr.signature) : null,
        ),
        h('div', { className: 'dshf-f-actions' },
          h('button', {
            className: 'dshf-mini', title: '改备注',
            onClick: () => { setDraft(fr.alias || ''); setRenaming(true) },
          }, h(MiniIcon, { path: ICON_PENCIL })),
          h('button', {
            className: 'dshf-mini', title: '戳一戳',
            disabled: !fr.online,
            onClick: () => store.poke(fr.code),
          }, h(MiniIcon, { path: ICON_POKE })),
          h('button', {
            className: 'dshf-mini', title: '删除好友',
            onClick: async () => { if (confirm('删除好友 ' + name + '？对方也会看到你删了他')) { await store.removeFriend(fr.code); onChange && onChange() } },
          }, h(MiniIcon, { path: ICON_TRASH })),
        ),
      )
    }

    function Panel() {
      const storeRef = React.useRef(null)
      if (!storeRef.current) storeRef.current = createStore()
      const store = storeRef.current
      // 调试/测试钩子：让 harness 能拿到 store 实例（渲染验证用）
      try { window.__dshfStore = store } catch (e) { /* ignore */ }
      const [, force] = React.useReducer((x) => x + 1, 0)
      const [editing, setEditing] = React.useState(false)
      const [settings, setSettings] = React.useState(false)
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

      const onlineCount = friends.filter((f) => f.online).length
      const incCount = (s.me && s.me.requests.incoming) ? s.me.requests.incoming.length : 0
      const secTitle = friends.length === 0
        ? '好友'
        : '好友 · ' + friends.length + '（在线 ' + onlineCount + '）'

      return h('div', { className: 'dshf-wrap' },
        h('div', { className: 'dshf-head' },
          h('div', { className: 'dshf-title' }, '🐳 鲸友',
            incCount > 0 ? h('span', { className: 'dshf-badge', title: incCount + ' 条好友请求待处理' }, String(incCount)) : null,
            h('button', {
              className: 'dshf-mini', title: '切换中继节点',
              style: { marginLeft: 'auto' },
              onClick: () => store.rotateBroker(),
            }, '⇄'),
          ),
          h('div', { className: 'dshf-conn ' + (s.conn === 'connected' ? 'ok' : 'bad') }, connText),
        ),
        h(MeCard, { store, editing, setEditing }),
        h('div', { className: 'dshf-actions' },
          h('button', { className: 'dshf-btn', onClick: () => setEditing((v) => !v) }, editing ? '收起' : '编辑资料 / 签名'),
          h('button', {
            className: 'dshf-btn', onClick: () => setSettings((v) => !v),
            style: settings ? { borderColor: 'var(--dshf-accent)' } : null,
          }, settings ? '收起设置' : '加好友设置'),
          friends.length > 0
            ? h('span', { style: { marginLeft: 'auto', fontSize: 11.5, color: 'var(--dshf-fg-dim)', alignSelf: 'center' } },
                onlineCount > 0 ? onlineCount + ' 位在线' : '全部离线')
            : null,
        ),
        editing ? h(EditCard, { store, onClose: () => setEditing(false) }) : null,
        settings ? h(SettingsCard, { store, onClose: () => setSettings(false) }) : null,
        h(AddRow, { store }),
        h(RequestsCard, { store }),
        h('div', { className: 'dshf-sec' }, secTitle),
        h('div', { className: 'dshf-list' },
          friends.length === 0
            ? h('div', { className: 'dshf-empty' },
                '还没有好友。', h('br'),
                '把你的 ', bold('好友码'), ' 发给同样在用 DSH 的朋友，双方互加后，',
                '就能看到对方是否在线、模型是不是在跑任务。',
                s.me ? h('span', {
                  className: 'dshf-empty-code', title: '点击复制',
                  onClick: () => copyText(s.me.code),
                }, s.me.code) : null,
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
        // 轻提示（好友请求被同意等）
        ...(s.toasts || []).map((t) => h('div', { key: t.key, className: 'dshf-toast' }, t.text)),
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
