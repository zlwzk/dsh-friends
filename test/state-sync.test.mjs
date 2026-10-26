// 端到端验证「状态槽 retain」：模拟真实的错峰场景。
//
// 场景：A 和 B 是好友。A 上线发了状态后关掉 DSH；B 之后才打开 DSH。
// 老实现下 B 什么也看不到（A 的心跳早丢了），只能干等 A 再上线。
// 现在 B 一订阅 A 的状态槽，中继立刻把 A 最后那条状态推过来。
import { test } from 'node:test'
import { WebSocket } from 'ws'
import assert from 'node:assert'
import { webcrypto } from 'node:crypto'

globalThis.WebSocket = WebSocket
if (!globalThis.crypto) Object.defineProperty(globalThis, 'crypto', { value: webcrypto })

const { createMqttClient, deriveKey, sealJson, openJson, BROKERS } = await import('../lib/relay-core.mjs')

const BROKER = process.env.DSH_FRIENDS_BROKER || BROKERS[1]
const wait = (ms) => new Promise((r) => setTimeout(r, ms))

async function waitUntil(pred, timeout) {
  const start = Date.now()
  while (Date.now() - start < timeout) {
    if (pred()) return true
    await wait(100)
  }
  return false
}

const tag = Math.random().toString(36).slice(2, 8)
const CODE_A = 'RTA' + tag.slice(0, 3).toUpperCase().replace(/[^A-HJ-NP-Z2-9]/g, 'A')
const CODE_B = 'RTB' + tag.slice(3, 6).toUpperCase().replace(/[^A-HJ-NP-Z2-9]/g, 'B')

/** 和 client.js 的 stateTopicOf 保持一致。 */
const stateTopicOf = (myCode, peerCode) => 'dshf/s/' + peerCode.toUpperCase() + '/' + myCode.toUpperCase()

test('a friend who comes online later still sees the last known state', async () => {
  const subtle = webcrypto.subtle
  // A 写给 B 的状态槽：话题里 B 是收件人，A 是发送者
  const slot = stateTopicOf(CODE_A, CODE_B)

  const stateMsg = {
    kind: 'presence', id: 'a-id',
    nickname: '阿改', signature: '别戳，在 debug。', mood: '🛠',
    status: 'busy', label: '跑一个长任务', ts: Date.now(),
  }
  const sealed = await sealJson(stateMsg, await deriveKey(CODE_B, subtle), subtle)

  // ---- 1) A 上线，把状态写进保留槽，然后下线 ----
  const a = createMqttClient({ url: BROKER, clientId: 'rta-' + tag, onStatus: () => {}, onMessage: () => {} })
  a.start()
  assert.ok(await waitUntil(() => a.isConnected(), 12000), 'A connected')
  await wait(400)
  a.publish(slot, new TextEncoder().encode(sealed), true)
  await wait(1500)
  a.stop()
  await wait(800)

  // ---- 2) B 这时才上线，订阅后应立刻收到 A 的状态 ----
  const got = []
  const b = createMqttClient({
    url: BROKER, clientId: 'rtb-' + tag, onStatus: () => {},
    onMessage: (t, payload) => { if (t === slot) got.push(new TextDecoder().decode(payload)) },
  })
  try {
    b.start()
    assert.ok(await waitUntil(() => b.isConnected(), 12000), 'B connected')
    b.subscribe(slot)
    assert.ok(await waitUntil(() => got.length > 0, 8000), 'B receives retained state')

    // 内容必须完整：昵称、签名、忙碌状态都要在
    const opened = await openJson(got[0], await deriveKey(CODE_B, subtle), subtle)
    assert.ok(opened, 'retained payload decrypts with the recipient code')
    assert.equal(opened.nickname, '阿改')
    assert.equal(opened.signature, '别戳，在 debug。')
    assert.equal(opened.status, 'busy')
    assert.equal(opened.label, '跑一个长任务')
  } finally {
    b.stop()
    // 清掉保留槽，避免污染公共中继上的这个测试话题
    const c = createMqttClient({ url: BROKER, clientId: 'rtc-' + tag, onStatus: () => {}, onMessage: () => {} })
    c.start()
    await waitUntil(() => c.isConnected(), 12000)
    await wait(300)
    c.publish(slot, new Uint8Array(0), true)
    await wait(500)
    c.stop()
  }
})

test('signing off overwrites the slot with an offline marker', async () => {
  const subtle = webcrypto.subtle
  const slot = stateTopicOf(CODE_A, CODE_B)

  // 先写一条「在线」
  const online = await sealJson(
    { kind: 'presence', nickname: '阿改', status: 'online', ts: Date.now() },
    await deriveKey(CODE_B, subtle), subtle,
  )
  // 再写一条「offline 标记」
  const offlineMsg = { kind: 'presence', id: 'a-id', offline: true, ts: Date.now() + 1 }
  const offline = await sealJson(offlineMsg, await deriveKey(CODE_B, subtle), subtle)

  const got = []
  const w = createMqttClient({ url: BROKER, clientId: 'rtw-' + tag, onStatus: () => {}, onMessage: () => {} })
  try {
    w.start()
    assert.ok(await waitUntil(() => w.isConnected(), 12000), 'writer connected')
    await wait(300)
    w.publish(slot, new TextEncoder().encode(online), true)
    await wait(1200)
    // 下线时改写为离线标记（client.js 的 sendBye 就是这么做的）
    w.publish(slot, new TextEncoder().encode(offline), true)
    await wait(1500)
  } finally {
    w.stop()
  }

  const r = createMqttClient({
    url: BROKER, clientId: 'rtr-' + tag, onStatus: () => {},
    onMessage: (t, p) => { if (t === slot) got.push(new TextDecoder().decode(p)) },
  })
  try {
    r.start()
    assert.ok(await waitUntil(() => r.isConnected(), 12000), 'reader connected')
    r.subscribe(slot)
    assert.ok(await waitUntil(() => got.length > 0, 8000), 'reader receives slot')
    const opened = await openJson(got[0], await deriveKey(CODE_B, subtle), subtle)
    assert.ok(opened, 'decrypts')
    // 保留槽里必须是最后写的那条：离线标记，而不是旧的「在线」
    assert.equal(opened.offline, true, 'slot holds the offline marker, not the stale online state')
  } finally {
    r.stop()
    const c = createMqttClient({ url: BROKER, clientId: 'rtc2-' + tag, onStatus: () => {}, onMessage: () => {} })
    c.start()
    await waitUntil(() => c.isConnected(), 12000)
    await wait(300)
    c.publish(slot, new Uint8Array(0), true)
    await wait(500)
    c.stop()
  }
})
