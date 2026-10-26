// dsh-friends relay core —— 零依赖的实时层。
//
// 设计：
//   - 传输：MQTT 3.1.1 over WebSocket(Secure)，只实现需要的报文：
//       CONNECT(1) / CONNACK(2) / PUBLISH(3) / SUBSCRIBE(8) / SUBACK(9)
//       PINGREQ(12) / PINGRESP(13) / DISCONNECT(14)。qos 0 即可，状态消息
//       高频且可丢，不需要重传。
//   - 拓扑：每个好友码 F 是一个"圈子"。某用户的好友码为 own，他订阅
//       dshf/u/<own>      接收别人（加了他的好友）发来的 presence/动作
//     发布到
//       dshf/u/<friendCode>  发给某个好友
//     双向加好友 = 各自订阅自己、向对方发心跳；对方若也加了你，就会回发，
//     于是双方互见。单方加好友只会单向看到（悄悄关注），产品上我们鼓励互给码。
//   - 加密：payload 用 AES-GCM，密钥 = SHA-256("dsh-friends/v1:" + 好友码)。
//     好友码本身是 6 位、线下/私聊交换的共享密钥；频道主题虽可被猜到，但没有
//     码就派生不出密钥，broker 与旁观者只能看到密文。每条消息带随机 IV。
//
// 该文件同时被 client 浏览器使用：不引用任何 node API（crypto 由调用方注入）。

/** 编码 MQTT UTF-8 字符串（2 字节长度前缀）。 */
function encodeStr(buf) {
  const out = new Uint8Array(2 + buf.length)
  out[0] = (buf.length >> 8) & 0xff
  out[1] = buf.length & 0xff
  out.set(buf, 2)
  return out
}

/** MQTT 剩余长度可变编码。 */
function encodeRemainingLength(len) {
  const bytes = []
  do {
    let b = len % 128
    len = Math.floor(len / 128)
    if (len > 0) b |= 0x80
    bytes.push(b)
  } while (len > 0)
  return new Uint8Array(bytes)
}

function concat(list) {
  let n = 0
  for (const b of list) n += b.length
  const out = new Uint8Array(n)
  let o = 0
  for (const b of list) { out.set(b, o); o += b.length }
  return out
}

function packet(typeNibble, body, flags = 0) {
  return concat([new Uint8Array([(typeNibble << 4) | flags]), encodeRemainingLength(body.length), body])
}

/**
 * 极简 MQTT-over-WS 客户端。
 * @param {object} opts
 * @param {string} opts.url  wss://host:port/mqtt
 * @param {string} opts.clientId
 * @param {number[]} [opts.subprotocol]  通常 ['mqtt']
 * @param {(topic:string, payload:Uint8Array)=>void} opts.onMessage
 * @param {(status:string, detail?:any)=>void} [opts.onStatus]
 * @param {Crypto-like subtle} 不需要，加密在外层
 */
export function createMqttClient(opts) {
  const { url, clientId, onMessage, onStatus } = opts
  let ws = null
  let connected = false
  let closedByUser = false
  let pingTimer = null
  let reconnectTimer = null
  let reconnectDelay = 800
  const subscriptions = new Set()
  let packetId = 1

  const setStatus = (s, detail) => { try { onStatus && onStatus(s, detail) } catch { /* ignore */ } }

  const connect = () => {
    if (closedByUser) return
    let WSCtor = (typeof WebSocket !== 'undefined') ? WebSocket : null
    if (!WSCtor) { setStatus('unsupported'); return }
    try {
      ws = new WSCtor(url, ['mqtt'])
    } catch (e) {
      scheduleReconnect(e)
      return
    }
    ws.binaryType = 'arraybuffer'
    ws.onopen = () => {
      // CONNECT, protocol level 4 (3.1.1), clean session, keepalive 25s.
      const te = new TextEncoder()
      const variable = concat([
        encodeStr(te.encode('MQTT')),
        new Uint8Array([4, 0x02, 0, 25]),
        encodeStr(te.encode(clientId)),
      ])
      ws.send(packet(1, variable))
    }
    ws.onmessage = (ev) => {
      const d = new Uint8Array(ev.data)
      if (d.length < 2) return
      const type = d[0] >> 4
      if (type === 2) { // CONNACK
        const rc = d[3]
        if (rc !== 0) { setStatus('rejected', rc); try { ws.close() } catch { /* */ } return }
        connected = true
        reconnectDelay = 800
        setStatus('connected')
        // 重新订阅
        for (const topic of Array.from(subscriptions)) sendSubscribe(topic)
        // 心跳
        stopPing()
        pingTimer = setInterval(() => {
          if (connected && ws && ws.readyState === 1) {
            try { ws.send(packet(12, new Uint8Array(0))) } catch { /* */ }
          }
        }, 20000)
      } else if (type === 3) { // PUBLISH (qos0)
        let i = 2
        // 跳过 remaining length（可能多字节）
        // d[0]=固定头, 从 index 1 解析剩余长度
        let rlLen = 1
        {
          let mult = 1
          let val = 0
          let p = 1
          do {
            const b = d[p]
            val += (b & 127) * mult
            mult *= 128
            if (!(b & 128)) { rlLen = p; break }
            p++
          } while (true)
          i = rlLen + 1
        }
        const topicLen = (d[i] << 8) | d[i + 1]
        i += 2
        const topic = new TextDecoder().decode(d.slice(i, i + topicLen))
        i += topicLen
        const payload = d.slice(i)
        try { onMessage(topic, payload) } catch (e) { /* consumer error */ }
      } else if (type === 13) { // PINGRESP
        // alive
      }
    }
    ws.onerror = () => { /* close 会兜底 */ }
    ws.onclose = () => {
      connected = false
      stopPing()
      if (!closedByUser) scheduleReconnect()
    }
  }

  const stopPing = () => { if (pingTimer) { clearInterval(pingTimer); pingTimer = null } }

  const scheduleReconnect = (detail) => {
    if (closedByUser) return
    setStatus('reconnecting', detail && detail.message)
    clearTimeout(reconnectTimer)
    reconnectTimer = setTimeout(() => {
      reconnectDelay = Math.min(reconnectDelay * 1.6, 15000)
      connect()
    }, reconnectDelay)
  }

  const sendSubscribe = (topic) => {
    if (!connected || !ws || ws.readyState !== 1) return
    const te = new TextEncoder()
    packetId = (packetId % 65535) + 1
    const pid = new Uint8Array([(packetId >> 8) & 0xff, packetId & 0xff])
    const body = concat([pid, encodeStr(te.encode(topic)), new Uint8Array([0])]) // qos0
    ws.send(packet(8, body, 0x02))
  }

  const api = {
    start() { closedByUser = false; connect() },
    subscribe(topic) { subscriptions.add(topic); if (connected) sendSubscribe(topic) },
    unsubscribe(topic) { subscriptions.delete(topic) },
    isConnected() { return connected },
    /**
     * 发布 qos0。retain=true 时让中继保存最后一条：订阅者（重新）连上就立刻
     * 收到，不必等对方下一次心跳。状态类消息必须 retain——否则对方离线期间
     * 发的那条状态彻底丢失，这正是"看不到在线/签名"的根因。
     */
    publish(topic, payload, retain) {
      if (!connected || !ws || ws.readyState !== 1) return false
      const te = new TextEncoder()
      const body = concat([encodeStr(te.encode(topic)), payload])
      ws.send(packet(3, body, retain ? 0x01 : 0))
      return true
    },
    stop() {
      closedByUser = true
      stopPing()
      clearTimeout(reconnectTimer)
      try { if (connected && ws) ws.send(packet(14, new Uint8Array(0))) } catch { /* */ }
      try { ws && ws.close() } catch { /* */ }
      connected = false
    },
  }
  return api
}

// ------------------------------------------------------------ crypto

const enc = new TextEncoder()
const dec = new TextDecoder()

/** 由好友码派生 AES-GCM 256 位密钥。 */
export async function deriveKey(friendCode, subtle) {
  const material = await subtle.importKey(
    'raw',
    enc.encode('dsh-friends/v1:' + friendCode.toUpperCase()),
    { name: 'HKDF' },
    false,
    ['deriveKey'],
  )
  return subtle.deriveKey(
    { name: 'HKDF', hash: 'SHA-256', salt: enc.encode('dsh-friends-presence'), info: enc.encode('aes-gcm') },
    material,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt'],
  )
}

/** 加密 JSON -> base64 字符串（iv|ciphertext|tag 由 WebCrypto 拼在一起）。 */
export async function sealJson(obj, key, subtle) {
  const iv = crypto.getRandomValues(new Uint8Array(12))
  const cipher = new Uint8Array(await subtle.encrypt({ name: 'AES-GCM', iv }, key, enc.encode(JSON.stringify(obj))))
  const all = concat([iv, cipher])
  return toBase64(all)
}

/** 解密 base64 字符串 -> JSON；失败返回 null（可能是错误好友码/旧消息）。 */
export async function openJson(b64, key, subtle) {
  try {
    const all = fromBase64(b64)
    const iv = all.slice(0, 12)
    const data = all.slice(12)
    const plain = new Uint8Array(await subtle.decrypt({ name: 'AES-GCM', iv }, key, data))
    return JSON.parse(dec.decode(plain))
  } catch {
    return null
  }
}

// base64 <-> bytes，浏览器和 node18+ 都能用（优先用环境自带）。
export function toBase64(bytes) {
  if (typeof btoa === 'function') {
    let bin = ''
    for (let i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i])
    return btoa(bin)
  }
  return Buffer.from(bytes).toString('base64')
}
export function fromBase64(b64) {
  if (typeof atob === 'function') {
    const bin = atob(b64)
    const out = new Uint8Array(bin.length)
    for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i)
    return out
  }
  return new Uint8Array(Buffer.from(b64, 'base64'))
}

/** 合法好友码（6 位大写去歧义字符）。 */
export function isValidCode(code) {
  return typeof code === 'string' && /^[A-HJ-NP-Z2-9]{6}$/.test(String(code).toUpperCase())
}

export const BROKERS = [
  'wss://broker.emqx.io:8084/mqtt',
  'wss://broker.hivemq.com:8884/mqtt',
]

/**
 * 并发探测候选 broker，返回第一个能完成 MQTT 握手的。
 *
 * 公共 broker 会抖动/区域性不可达（实测 emqx 在部分时段完全 time out），
 * 若启动时死磕 BROKERS[0]，用户会看到几十秒「连接中」。这里给每个 broker
 * 8 秒窗口，全部失败则抛错，由调用方走重试。
 */
export function pickBroker(urls = BROKERS, timeoutMs = 8000) {
  const te = new TextEncoder()
  return new Promise((resolve, reject) => {
    let settled = false
    let pending = urls.length
    if (pending === 0) return reject(new Error('no broker candidates'))

    const finish = (value, error) => {
      if (settled) return
      settled = true
      if (error) reject(error)
      else resolve(value)
    }

    for (const url of urls) {
      let ws = null
      let done = false
      const timer = setTimeout(() => {
        if (done) return
        done = true
        try { ws && ws.close() } catch { /* ignore */ }
        if (--pending === 0) finish(null, new Error('所有公共中继节点均不可达'))
      }, timeoutMs)

      try {
        ws = new WebSocket(url, ['mqtt'])
      } catch {
        if (!done) { done = true; clearTimeout(timer); if (--pending === 0) finish(null, new Error('WebSocket 不可用')) }
        continue
      }
      ws.binaryType = 'arraybuffer'
      ws.onopen = () => {
        const vh = concat([encodeStr(te.encode('MQTT')), new Uint8Array([4, 2, 0, 25]),
          encodeStr(te.encode('dshf-probe-' + Math.random().toString(36).slice(2, 8)))])
        try { ws.send(packet(1, vh)) } catch { /* ignore */ }
      }
      ws.onmessage = (ev) => {
        if (done) return
        const d = new Uint8Array(ev.data)
        if ((d[0] >> 4) !== 2) return
        done = true
        clearTimeout(timer)
        try { ws.close() } catch { /* ignore */ }
        if (d[d.length - 1] === 0) finish(url, null)
        else if (--pending === 0) finish(null, new Error('所有公共中继节点均拒绝连接'))
      }
      ws.onerror = () => {}
      ws.onclose = () => {
        if (done) return
        done = true
        clearTimeout(timer)
        if (--pending === 0) finish(null, new Error('所有公共中继节点均不可达'))
      }
    }
  })
}
