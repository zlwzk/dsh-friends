// Node 端互通测试：两个"好友"经公共 broker + AES-GCM 互发 presence。
// 用 node --test 跑；ws 由 DSH 桌面 profile 的 node_modules 提供（测试期）。
import { test } from 'node:test'
import assert from 'node:assert'
import { WebSocket } from 'ws'
import { webcrypto } from 'node:crypto'

// 让 relay-core 看到浏览器式环境（node24 全局 crypto 只读且已是 webcrypto）
globalThis.WebSocket = WebSocket
if (!globalThis.crypto) Object.defineProperty(globalThis, 'crypto', { value: webcrypto })

const {
  createMqttClient,
  deriveKey,
  sealJson,
  openJson,
  isValidCode,
  pickBroker,
  BROKERS,
} = await import('../lib/relay-core.mjs')

const BROKER = process.env.DSH_FRIENDS_BROKER || BROKERS[1] // hivemq 默认：emqx 常被墙/抖动
const CODE = 'ABC234' // 测试码

function wait(ms) { return new Promise((r) => setTimeout(r, ms)) }

test('pickBroker finds at least one reachable public relay', async () => {
  const picked = await pickBroker(BROKERS, 9000)
  assert.ok(BROKERS.includes(picked), 'picked one of the candidates: ' + picked)
})

test('isValidCode accepts canonical alphabet', () => {
  assert.ok(isValidCode('ABC234'))
  assert.ok(isValidCode('abc234')) // 小写归一
  assert.ok(!isValidCode('ABCD01')) // 含 0/1/I/L 等
  assert.ok(!isValidCode('AB'))
})

test('crypto seal/open round trip and tamper rejection', async () => {
  const subtle = webcrypto.subtle
  const key = await deriveKey(CODE, subtle)
  const msg = { kind: 'presence', nickname: '小鲸', ts: Date.now() }
  const sealed = await sealJson(msg, key, subtle)
  assert.equal(typeof sealed, 'string')
  const opened = await openJson(sealed, key, subtle)
  assert.deepEqual(opened, msg)
  // 错误密钥解不开
  const other = await deriveKey('ZZZ999', subtle)
  assert.equal(await openJson(sealed, other, subtle), null)
})

test('two clients exchange encrypted presence over the public broker', async () => {
  const subtle = webcrypto.subtle
  const key = await deriveKey(CODE, subtle)
  const suffix = Math.random().toString(36).slice(2, 8)
  const topicA = 'dshf/test/' + suffix + '/a'
  const topicB = 'dshf/test/' + suffix + '/b'

  const gotByB = []
  const gotByA = []

  const a = createMqttClient({
    url: BROKER,
    clientId: 'dshfA' + suffix,
    onStatus: () => {},
    async onMessage(topic, payload) {
      const obj = await openJson(new TextDecoder().decode(payload), key, subtle)
      if (obj) gotByA.push({ topic, obj })
    },
  })
  const b = createMqttClient({
    url: BROKER,
    clientId: 'dshfB' + suffix,
    onStatus: () => {},
    async onMessage(topic, payload) {
      const obj = await openJson(new TextDecoder().decode(payload), key, subtle)
      if (obj) gotByB.push({ topic, obj })
    },
  })

  try {
    a.start(); b.start()
    a.subscribe(topicA)
    b.subscribe(topicB)

    // 等订阅生效
    await waitUntil(() => a.isConnected() && b.isConnected(), 12000)
    await wait(800)

    // 公共 broker 偶发丢消息/慢，最多重试 3 轮再断言。
    for (let attempt = 0; attempt < 3 && (gotByA.length < 1 || gotByB.length < 1); attempt++) {
      await a.publish(topicB, new TextEncoder().encode(await sealJson({ kind: 'presence', from: 'A' }, key, subtle)))
      await b.publish(topicA, new TextEncoder().encode(await sealJson({ kind: 'presence', from: 'B' }, key, subtle)))
      await waitUntil(() => gotByA.length >= 1 && gotByB.length >= 1, 6000).catch(() => {})
    }

    await waitUntil(() => gotByA.length >= 1 && gotByB.length >= 1, 8000)
    assert.equal(gotByB[0].obj.from, 'A')
    assert.equal(gotByA[0].obj.from, 'B')
  } finally {
    a.stop(); b.stop()
  }
})

async function waitUntil(pred, timeout) {
  const start = Date.now()
  while (Date.now() - start < timeout) {
    if (pred()) return true
    await wait(150)
  }
  throw new Error('condition timeout')
}
