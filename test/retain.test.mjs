// 验证 MQTT retain 是否真的生效：
// A 发一条 retained 消息后断开；随后 B 才订阅同一话题，B 应该立刻收到。
// 这是「好友离线期间的状态不丢」的核心前提，必须实测而不是假设。
import { WebSocket } from 'ws'
import { createMqttClient, BROKERS } from '../lib/relay-core.mjs'

const BROKER = BROKERS[1]
const tag = Math.random().toString(36).slice(2, 8)
const topic = 'dshf/retaintest/' + tag + '/state'
const wait = (ms) => new Promise((r) => setTimeout(r, ms))

async function waitUntil(pred, timeout) {
  const start = Date.now()
  while (Date.now() - start < timeout) {
    if (pred()) return true
    await wait(100)
  }
  return false
}

const gotByB = []

const a = createMqttClient({
  url: BROKER, clientId: 'ra-' + tag, onStatus: () => {},
  onMessage: () => {},
})
a.start()
const okA = await waitUntil(() => a.isConnected(), 12000)
if (!okA) { console.log('A 连接失败'); process.exit(1) }
await wait(400)

// A 发 retained 消息
const payload = new TextEncoder().encode(JSON.stringify({ nickname: '阿改', signature: '别戳，在 debug', online: true }))
a.publish(topic, payload, true)
await wait(1200)

// A 直接关掉（模拟"对方离线后我才上线"）
a.stop()
await wait(800)

// B 这时才开始订阅
const b = createMqttClient({
  url: BROKER, clientId: 'rb-' + tag, onStatus: () => {},
  onMessage: (t, p) => {
    if (t === topic) gotByB.push(new TextDecoder().decode(p))
  },
})
b.start()
const okB = await waitUntil(() => b.isConnected(), 12000)
if (!okB) { console.log('B 连接失败'); b.stop(); process.exit(1) }
b.subscribe(topic)

const got = await waitUntil(() => gotByB.length > 0, 6000)
b.stop()

if (got) {
  console.log('PASS: 订阅后立即收到 retained 状态 ->', gotByB[0].slice(0, 80))
  // 清理 retained 消息（发空 payload 且 retain=true 即可清除）
  const c = createMqttClient({ url: BROKER, clientId: 'rc-' + tag, onStatus: () => {}, onMessage: () => {} })
  c.start()
  await waitUntil(() => c.isConnected(), 12000)
  await wait(300)
  c.publish(topic, new Uint8Array(0), true)
  await wait(600)
  c.stop()
  process.exit(0)
} else {
  console.log('FAIL: 订阅后没收到 retained 消息（该中继可能不支持 retain）')
  process.exit(1)
}
