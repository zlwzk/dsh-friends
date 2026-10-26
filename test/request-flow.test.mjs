// 好友申请协议的端到端测试：A 申请 B → B 解密后知道是 A → B 同意 → A 收到 accept。
//
// 这一组之所以存在：之前的实现里接收端只拿「好友 + 已知申请」的码去解密，
// 而申请是用「收件人的码」加密的，于是 B 永远解不开 A 的申请，
// UI 上的「同意」按钮也就永远不出现。下面的用例把那条链路钉住。
import { test } from 'node:test'
import { WebSocket } from 'ws'
import assert from 'node:assert'
import { webcrypto } from 'node:crypto'

globalThis.WebSocket = WebSocket
if (!globalThis.crypto) Object.defineProperty(globalThis, 'crypto', { value: webcrypto })

const { createMqttClient, deriveKey, sealJson, openJson, isValidCode, BROKERS } = await import('../lib/relay-core.mjs')

const BROKER = process.env.DSH_FRIENDS_BROKER || BROKERS[1]
const wait = (ms) => new Promise((r) => setTimeout(r, ms))

async function waitUntil(pred, timeout) {
  const start = Date.now()
  while (Date.now() - start < timeout) {
    if (pred()) return true
    await wait(120)
  }
  throw new Error('condition timeout')
}

const suffix = Math.random().toString(36).slice(2, 7)
const CODE_A = 'AAA' + suffix.slice(0, 2).toUpperCase().replace(/[^A-HJ-NP-Z2-9]/g, 'X')
const CODE_B = 'BBB' + suffix.slice(2, 4).toUpperCase().replace(/[^A-HJ-NP-Z2-9]/g, 'Y')

/** 模拟 client.js 里「按候选码逐个解密」的逻辑，重点是自己的码必须排第一。 */
function candidateCodes(me) {
  const out = []
  const seen = new Set()
  const add = (c) => {
    if (typeof c !== 'string') return
    const up = c.toUpperCase()
    if (!seen.has(up)) { seen.add(up); out.push(up) }
  }
  add(me.code)                                   // ← 别人发给我的消息都用我的码加密
  for (const f of me.friends || []) add(f.code)
  for (const r of (me.requests && me.requests.incoming) || []) add(r.code)
  for (const r of (me.requests && me.requests.outgoing) || []) add(r.code)
  return out
}

async function givenCode(prefix) {
  // 生成一个合法且唯一的 6 位码
  let c = prefix
  while (c.length < 6) c += 'ABCDEFGHJKMNPQRSTUVWXYZ23456789'[Math.floor(Math.random() * 29)]
  return c.slice(0, 6)
}

test('a friend request can actually be decrypted by the recipient', async () => {
  const subtle = webcrypto.subtle
  const codeA = await givenCode(CODE_A.replace(/[^A-HJ-NP-Z2-9]/g, 'A'))
  const codeB = await givenCode(CODE_B.replace(/[^A-HJ-NP-Z2-9]/g, 'B'))
  assert.ok(isValidCode(codeA), 'A code valid: ' + codeA)
  assert.ok(isValidCode(codeB), 'B code valid: ' + codeB)
  assert.notEqual(codeA, codeB)

  const tag = Math.random().toString(36).slice(2, 7)
  const topicA = 'dshf/reqtest/' + tag + '/a'
  const topicB = 'dshf/reqtest/' + tag + '/b'

  // A 还没加任何人；B 也还没有 A（关键：B 的候选码集合里没有 A 的码）
  const meA = { code: codeA, friends: [], requests: { incoming: [], outgoing: [] } }
  const meB = { code: codeB, friends: [], requests: { incoming: [], outgoing: [] } }

  const gotByB = []
  const gotByA = []

  const a = createMqttClient({
    url: BROKER, clientId: 'reqA' + tag, onStatus: () => {},
    async onMessage(_t, payload) {
      const text = new TextDecoder().decode(payload)
      for (const c of candidateCodes(meA)) {
        const msg = await openJson(text, await deriveKey(c, subtle), subtle)
        if (msg) { gotByA.push(msg); return }
      }
    },
  })
  const b = createMqttClient({
    url: BROKER, clientId: 'reqB' + tag, onStatus: () => {},
    async onMessage(_t, payload) {
      const text = new TextDecoder().decode(payload)
      for (const c of candidateCodes(meB)) {
        const msg = await openJson(text, await deriveKey(c, subtle), subtle)
        if (msg) { gotByB.push(msg); return }
      }
    },
  })

  try {
    a.start(); b.start()
    a.subscribe(topicA); b.subscribe(topicB)
    await waitUntil(() => a.isConnected() && b.isConnected(), 12000)
    await wait(600)

    // ---- A -> B：申请（用 B 的码加密，和 client.js 的 sendTo 一致） ----
    const req = {
      kind: 'friend_request', from: meA.code, fromCode: codeA,
      fromNickname: '小A', message: '我是小A', ts: Date.now(),
    }
    const sealedReq = await sealJson(req, await deriveKey(codeB, subtle), subtle)
    for (let i = 0; i < 3 && gotByB.length === 0; i++) {
      await a.publish(topicB, new TextEncoder().encode(sealedReq))
      await waitUntil(() => gotByB.length >= 1, 5000).catch(() => {})
    }
    await waitUntil(() => gotByB.length >= 1, 8000)

    const received = gotByB[0]
    assert.equal(received.kind, 'friend_request')
    // 这是最关键的一条：B 必须能知道申请人是谁，否则没法回、也没法显示名字
    assert.equal(received.fromCode, codeA, 'recipient learns the requester code')

    // ---- B 同意：把 A 加为好友，回 accept ----
    meB.friends.push({ code: codeA, alias: '小A' })
    const accept = { kind: 'friend_accept', from: meB.code, fromCode: codeB, nickname: '小B', ts: Date.now() }
    const sealedAccept = await sealJson(accept, await deriveKey(codeA, subtle), subtle)
    for (let i = 0; i < 3 && gotByA.length === 0; i++) {
      await b.publish(topicA, new TextEncoder().encode(sealedAccept))
      await waitUntil(() => gotByA.length >= 1, 5000).catch(() => {})
    }
    await waitUntil(() => gotByA.length >= 1, 8000)

    const back = gotByA[0]
    assert.equal(back.kind, 'friend_accept')
    assert.equal(back.fromCode, codeB, 'requester learns who accepted')
    assert.equal(back.nickname, '小B')
  } finally {
    a.stop(); b.stop()
  }
})

test('recipient can decrypt with only its own code (the old bug)', async () => {
  const subtle = webcrypto.subtle
  const stranger = await givenCode('ZZQ')
  assert.ok(isValidCode(stranger), 'stranger code valid: ' + stranger)

  // 一个还没加过任何人的用户，候选码 = 自己的码
  const me = { code: stranger, friends: [], requests: { incoming: [], outgoing: [] } }
  const candidates = candidateCodes(me)
  assert.deepEqual(candidates, [stranger], 'own code must be a candidate even with zero friends')

  const msg = { kind: 'friend_request', fromCode: 'ABC234', fromNickname: '老王', ts: Date.now() }
  const sealed = await sealJson(msg, await deriveKey(stranger, subtle), subtle)

  let opened = null
  for (const c of candidates) {
    opened = await openJson(sealed, await deriveKey(c, subtle), subtle)
    if (opened) break
  }
  assert.ok(opened, 'a request addressed to me must decrypt with my own code')
  assert.equal(opened.fromCode, 'ABC234')
})

test('a request cannot be decrypted by someone who is not the addressee', async () => {
  const subtle = webcrypto.subtle
  const target = await givenCode('TGT')
  const other = await givenCode('OTH')
  const msg = { kind: 'friend_request', fromCode: 'ABC234', ts: Date.now() }
  const sealed = await sealJson(msg, await deriveKey(target, subtle), subtle)
  // 第三方用自己的码解不开
  const wrong = await openJson(sealed, await deriveKey(other, subtle), subtle)
  assert.equal(wrong, null)
})
