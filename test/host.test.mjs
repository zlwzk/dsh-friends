// host 侧测试：资料持久化、字段清洗、三个模型工具、HTTP 路由行为。
import { test } from 'node:test'
import assert from 'node:assert'
import { existsSync, mkdtempSync, readdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs'
import { join } from 'node:path'
import { tmpdir } from 'node:os'

// host 模块在 import 时就可能读 profile 吗？不会——只在 apply/工具 execute 里读。
// 用一个独立的数据目录，避免污染真实 ~/.dsh。
const DATA = mkdtempSync(join(tmpdir(), 'dsh-friends-test-'))
process.env.DSH_FRIENDS_HOME = DATA

const host = await import('../lib/index.js')

// 跑完清理临时数据目录，避免 tmpdir 堆积
process.on('exit', () => { try { rmSync(DATA, { recursive: true, force: true }) } catch { /* ignore */ } })

function wait(ms) { return new Promise((r) => setTimeout(r, ms)) }

/** 抓 apply(ctx) 注册的路由，返回 {routes, tools, dispose}。 */
function mountHost() {
  const routes = new Map()
  const tools = []
  const ctx = {
    tools: { register(def) { tools.push(def); return () => {} } },
    inject(services, cb) {
      const inner = {
        webServer: {
          register(desc) {
            routes.set(desc.path, desc.handler)
            return () => routes.delete(desc.path)
          },
        },
        effect() {},
      }
      cb(inner)
    },
  }
  const dispose = host.apply(ctx)
  return { routes, tools, dispose }
}

/** 发起一次假 HTTP 请求。 */
async function callRoute(routes, path, { method = 'GET', body } = {}) {
  const handler = routes.get(path)
  assert.ok(handler, 'route registered: ' + path)
  const chunks = body === undefined ? [] : [Buffer.from(JSON.stringify(body), 'utf8')]
  const request = {
    method,
    headers: body === undefined ? {} : { 'content-type': 'application/json' },
    on(ev, fn) {
      if (ev === 'data') for (const c of chunks) fn(c)
      if (ev === 'end') fn()
      if (ev === 'error') { /* no error path */ }
    },
    destroy() {},
  }
  const response = {
    statusCode: 0, headers: null, payload: '',
    writeHead(code, headers) { this.statusCode = code; this.headers = headers },
    end(body) { this.payload = body === undefined ? '' : String(body) },
  }
  await handler(request, response)
  return { status: response.statusCode, json: () => JSON.parse(response.payload || '{}'), raw: response.payload }
}

test('mount registers three tools and three routes', () => {
  const { routes, tools, dispose } = mountHost()
  const names = tools.map((t) => t.name).sort()
  assert.deepEqual(names, ['friend_profile', 'friend_sign_idea', 'friend_task'])
  assert.deepEqual([...routes.keys()].sort(), ['/dsh-friends/friends', '/dsh-friends/profile', '/dsh-friends/state'])
  assert.equal(typeof dispose, 'function')
  dispose()
})

test('GET /state creates and returns a self profile with friend code', async () => {
  const { routes } = mountHost()
  const res = await callRoute(routes, '/dsh-friends/state')
  assert.equal(res.status, 200)
  const s = res.json()
  assert.match(s.code, /^[A-HJ-NP-Z2-9]{6}$/)
  assert.equal(s.friends.length, 0)
  assert.equal(s.task.active, false)
  // 落盘了
  const file = join(DATA, 'profile.json')
  assert.ok(existsSync(file), 'profile persisted')
  const disk = JSON.parse(readFileSync(file, 'utf8'))
  assert.equal(disk.code, s.code)
})

test('POST /profile sanitizes length and rejects bad content type', async () => {
  const { routes } = mountHost()
  // 超长 nickname 应被截到 24，signature 截到 60
  const res = await callRoute(routes, '/dsh-friends/profile', {
    method: 'POST',
    body: { nickname: 'x'.repeat(50), signature: 'y'.repeat(100), mood: '🔥' },
  })
  assert.equal(res.status, 200)
  assert.equal(res.json().nickname.length, 24)
  assert.equal(res.json().signature.length, 60)
  assert.equal(res.json().mood, '🔥')
})

test('POST /friends validates friend codes and dedupes', async () => {
  const { routes } = mountHost()
  await callRoute(routes, '/dsh-friends/friends', {
    method: 'POST',
    body: { friends: [{ code: 'ABC234', alias: '小A' }, { code: 'abc234' }, { code: 'BAD0I1' }] },
  })
  const res = await callRoute(routes, '/dsh-friends/state')
  const friends = res.json().friends
  assert.equal(friends.length, 1, 'invalid code dropped, dupes merged')
  assert.equal(friends[0].code, 'ABC234')
  assert.equal(friends[0].alias, '小A')
})

test('route rejects non-JSON content type and wrong method', async () => {
  const { routes } = mountHost()
  const handler = routes.get('/dsh-friends/profile')
  const response = { writeHead(c) { this.statusCode = c }, end(b) { this.payload = b } }
  await handler({ method: 'POST', headers: { 'content-type': 'text/plain' }, on() {}, destroy() {} }, response)
  assert.equal(response.statusCode, 415)

  const res = await callRoute(routes, '/dsh-friends/state', { method: 'POST' })
  assert.equal(res.status, 405)
})

test('friend_task tool tracks running/idle/error lifecycle', async () => {
  const { routes, tools } = mountHost()
  const task = tools.find((t) => t.name === 'friend_task')
  const prof = tools.find((t) => t.name === 'friend_profile')

  await task.execute({ status: 'running', label: '正在重构插件' })
  let s = (await callRoute(routes, '/dsh-friends/state')).json()
  assert.equal(s.task.active, true)
  assert.equal(s.task.error, false)
  assert.equal(s.task.label, '正在重构插件')

  await task.execute({ status: 'error' })
  s = (await callRoute(routes, '/dsh-friends/state')).json()
  assert.equal(s.task.error, true)

  await task.execute({ status: 'idle' })
  s = (await callRoute(routes, '/dsh-friends/state')).json()
  assert.equal(s.task.active, false)

  // profile 工具：读 + 写
  const read = await prof.execute({})
  assert.ok(read.ok)
  const code = read.friendCode
  const written = await prof.execute({ signature: '测试签名' })
  assert.equal(written.friendCode, code)
  const after = (await callRoute(routes, '/dsh-friends/state')).json()
  assert.equal(after.signature, '测试签名')
})

test('friend_sign_idea enforces the 60-character limit', async () => {
  const { tools } = mountHost()
  const sign = tools.find((t) => t.name === 'friend_sign_idea')
  const ok = await sign.execute({ signature: 'a'.repeat(60) })
  assert.equal(ok.ok, true)
  assert.equal(ok.signature.length, 60)
  const tooLong = await sign.execute({ signature: 'a'.repeat(61) })
  assert.equal(tooLong.ok, false)
  assert.match(tooLong.error, /60/)
  const empty = await sign.execute({ signature: '   ' })
  assert.equal(empty.ok, false)
})

test('profile survives a corrupt file', async () => {
  const file = join(DATA, 'profile.json')
  const { routes } = mountHost()
  // 正常写一次
  await callRoute(routes, '/dsh-friends/profile', { method: 'POST', body: { nickname: '原主' } })
  // 破坏文件
  writeFileSync(file, '{ broken json', 'utf8')
  const after = (await callRoute(routes, '/dsh-friends/state')).json()
  // 备份重建：不再是原值，但仍是合法资料
  assert.notEqual(after.nickname, '原主')
  assert.match(after.code, /^[A-HJ-NP-Z2-9]{6}$/)
  // 备份文件存在（.corrupt-<timestamp>）
  const backups = readdirSync(DATA).filter((n) => n.startsWith('profile.json.corrupt-'))
  assert.ok(backups.length >= 1, 'corrupt file backed up: ' + backups.join(','))
})
