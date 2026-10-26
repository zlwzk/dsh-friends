// 诊断：两个 broker 现在是否可达 + 能否互通。独立脚本，不依赖 node --test。
import { WebSocket } from 'ws'

const BROKERS = ['wss://broker.emqx.io:8084/mqtt', 'wss://broker.hivemq.com:8884/mqtt']

function rawConnect(url, clientId) {
  return new Promise((resolve, reject) => {
    const ws = new WebSocket(url, ['mqtt'])
    const t = setTimeout(() => { try { ws.close() } catch {} ; reject(new Error('timeout')) }, 10000)
    ws.on('open', () => {
      const enc = new TextEncoder()
      const es = (s) => { const b = enc.encode(s); const x = new Uint8Array(2 + b.length); x[0] = b.length >> 8; x[1] = b.length & 255; x.set(b, 2); return x }
      const cat = (l) => { let n = 0; for (const b of l) n += b.length; const o = new Uint8Array(n); let p = 0; for (const b of l) { o.set(b, p); p += b.length } return o }
      const rl = (len) => { const b = []; do { let x = len % 128; len = Math.floor(len / 128); if (len > 0) x |= 0x80; b.push(x) } while (len > 0); return new Uint8Array(b) }
      const vh = cat([es('MQTT'), new Uint8Array([4, 2, 0, 25]), es(clientId)])
      ws.send(cat([new Uint8Array([0x10]), rl(vh.length), vh]))
    })
    ws.on('message', (d) => {
      const u = new Uint8Array(d)
      if ((u[0] >> 4) === 2) {
        clearTimeout(t)
        const rc = u[u.length - 1]
        if (rc === 0) { resolve(ws) } else { try { ws.close() } catch {} ; reject(new Error('CONNACK rc=' + rc)) }
      }
    })
    ws.on('error', (e) => { clearTimeout(t); reject(e) })
    ws.on('close', (c) => { clearTimeout(t); reject(new Error('closed ' + c)) })
  })
}

function pubRaw(ws, topic, payload) {
  const enc = new TextEncoder()
  const es = (s) => { const b = enc.encode(s); const x = new Uint8Array(2 + b.length); x[0] = b.length >> 8; x[1] = b.length & 255; x.set(b, 2); return x }
  const cat = (l) => { let n = 0; for (const b of l) n += b.length; const o = new Uint8Array(n); let p = 0; for (const b of l) { o.set(b, p); p += b.length } return o }
  const rl = (len) => { const b = []; do { let x = len % 128; len = Math.floor(len / 128); if (len > 0) x |= 0x80; b.push(x) } while (len > 0); return new Uint8Array(b) }
  const body = cat([es(topic), payload])
  ws.send(cat([new Uint8Array([0x30]), rl(body.length), body]))
}

function subRaw(ws, topic) {
  const enc = new TextEncoder()
  const es = (s) => { const b = enc.encode(s); const x = new Uint8Array(2 + b.length); x[0] = b.length >> 8; x[1] = b.length & 255; x.set(b, 2); return x }
  const cat = (l) => { let n = 0; for (const b of l) n += b.length; const o = new Uint8Array(n); let p = 0; for (const b of l) { o.set(b, p); p += b.length } return o }
  const rl = (len) => { const b = []; do { let x = len % 128; len = Math.floor(len / 128); if (len > 0) x |= 0x80; b.push(x) } while (len > 0); return new Uint8Array(b) }
  const body = cat([new Uint8Array([0, 1]), es(topic), new Uint8Array([0])])
  ws.send(cat([new Uint8Array([0x82]), rl(body.length), body]))
}

const suffix = Math.random().toString(36).slice(2, 7)
const topic = 'dshf/probe/' + suffix

for (const url of BROKERS) {
  let a, b
  try {
    a = await rawConnect(url, 'dshfPa' + suffix)
    process.stdout.write(url + ' connect A ok; ')
    b = await rawConnect(url, 'dshfPb' + suffix)
    process.stdout.write('connect B ok; ')
    const got = new Promise((resolve) => {
      b.on('message', (d) => {
        const u = new Uint8Array(d)
        if ((u[0] >> 4) === 3) resolve(true)
      })
    })
    subRaw(b, topic)
    await new Promise((r) => setTimeout(r, 500))
    pubRaw(a, topic, new TextEncoder().encode('ping'))
    const ok = await Promise.race([got, new Promise((r) => setTimeout(() => r(false), 4000))])
    console.log('pub/sub E2E: ' + (ok ? 'OK' : 'NO MESSAGE'))
    a.close(); b.close()
  } catch (e) {
    console.log('FAIL: ' + e.message)
    try { a && a.close() } catch {}
    try { b && b.close() } catch {}
  }
}
process.exit(0)
