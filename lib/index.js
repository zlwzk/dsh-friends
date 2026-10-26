// dsh-friends —— host half.
//
// 实时在线/消息通道完全在浏览器 client 侧（加密 MQTT-over-WSS），host 不发起
// 任何外联。host 只做三件本机的事：
//   1. 资料持久化：昵称、签名、心情 emoji、好友码、好友列表，存到
//      ~/.dsh/dsh-friends/profile.json（client 面板通过本插件的 HTTP 路由读写）。
//   2. 任务状态暂存：模型在一轮任务开始/结束时调用 friend_task 上报，
//      client 心跳读取后带给好友（离线重启自然清空，符合真实状态）。
//   3. 模型工具：friend_profile（查改自己资料）、friend_task（上报忙碌状态）、
//      friend_sign_idea（让模型根据最近的活写一条搞笑签名）、friend_inbox（查看好友请求）。
//   4. 好友申请设置：acceptMode（approve 需同意 / auto 无需同意）、stealth（隐身）、
//      好友请求收发箱，全部持久化在 profile.json。
//
// 与 dsh-wsl-tool 同一套挂载约定：export const name / inject，apply(ctx) 里
// 用 ctx.tools.register 注册工具，用 ctx.inject(['webServer']) 发布同源路由。

import { existsSync, mkdirSync, readFileSync, readdirSync, renameSync, writeFileSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { randomBytes } from 'node:crypto'

export const name = 'dsh-friends'
export const inject = ['tools']

const ROUTE_BASE = '/dsh-friends'
const MAX_BODY_BYTES = 64 * 1024

/** apply() 时记下的 profile 目录（用于列已安装插件），读不到就是 null。 */
let profileDirHint = null

/**
 * 资料目录：优先 $DSH_FRIENDS_HOME，否则 ~/.dsh/dsh-friends。
 * host 进程读不到 DSH_PROFILE_DIR（那是注入给工具子进程的），所以用 homedir。
 */
function dataDir() {
  const home = process.env.DSH_FRIENDS_HOME
    || join(process.env.USERPROFILE || process.env.HOME || '.', '.dsh', 'dsh-friends')
  return home
}

const PROFILE_FILE = () => join(dataDir(), 'profile.json')

const DEFAULT_PROFILE = () => ({
  // 稳定的本机身份 id（好友码之外的内部 id，用于去重）
  id: randomBytes(8).toString('hex'),
  nickname: '鲸友' + randomBytes(2).toString('hex').toUpperCase().slice(0, 4),
  signature: '这个人很神秘，还没有签名。',
  mood: '🐳',
  // 6 位好友码：加好友时双方各自把对方的码加进来；它同时派生出加密密钥与频道
  code: makeFriendCode(),
  friends: [],
  // 好友申请设置：approve=需要我同意（默认），auto=谁加都直接通过
  acceptMode: 'approve',
  // 隐身：在线但不向好友广播（心跳带 stealth 标记，好友侧显示为离线）
  stealth: false,
  // 好友请求（持久化，重启不丢）
  // incoming: [{ code, fromNickname, message, ts }]       别人加我，等我处理
  // outgoing: [{ code, message, ts, status }]             我加别人，等对方处理
  requests: { incoming: [], outgoing: [] },
  createdAt: new Date().toISOString(),
})

/** 生成易读的 6 位好友码（去掉易混字符 0/O/1/I/L）。 */
function makeFriendCode() {
  const alphabet = 'ABCDEFGHJKMNPQRSTUVWXYZ23456789'
  let out = ''
  const bytes = randomBytes(6)
  for (let i = 0; i < 6; i++) out += alphabet[bytes[i] % alphabet.length]
  return out
}

function clone(v) {
  return JSON.parse(JSON.stringify(v))
}

/** 读资料；文件不存在时初始化并落盘。损坏文件不静默覆盖，备份后重建。 */
function loadProfile() {
  const dir = dataDir()
  const file = PROFILE_FILE()
  if (!existsSync(dir)) mkdirSync(dir, { recursive: true })
  if (!existsSync(file)) {
    const fresh = DEFAULT_PROFILE()
    writeFileSync(file, JSON.stringify(fresh, null, 2), 'utf8')
    return fresh
  }
  try {
    const raw = readFileSync(file, 'utf8')
    const parsed = JSON.parse(raw)
    // 兜底补字段，向前兼容
    const base = DEFAULT_PROFILE()
    return { ...base, ...parsed, friends: Array.isArray(parsed.friends) ? parsed.friends : [] }
  } catch {
    const backup = file + '.corrupt-' + Date.now()
    try { renameSync(file, backup) } catch { /* ignore */ }
    const fresh = DEFAULT_PROFILE()
    writeFileSync(file, JSON.stringify(fresh, null, 2), 'utf8')
    return fresh
  }
}

/** 原子写：先写临时文件再 rename。 */
function saveProfile(profile) {
  const dir = dataDir()
  if (!existsSync(dir)) mkdirSync(dir, { recursive: true })
  const file = PROFILE_FILE()
  const tmp = file + '.tmp-' + process.pid
  writeFileSync(tmp, JSON.stringify(profile, null, 2), 'utf8')
  renameSync(tmp, file)
}

/** 内存里的实时任务状态（重启清空）。 */
const taskState = {
  active: false,
  label: '',
  startedAt: null,
  error: false,
}

/** 资料字段白名单与长度限制，防止 client 写入任意垃圾。 */
const STRING_LIMITS = {
  nickname: 24,
  signature: 60,
  mood: 8,
  alias: 24,
  message: 60,
}

const CODE_RE = /^[A-HJ-NP-Z2-9]{6}$/

/** 规范化好友记录（code/alias/addedAt）。 */
function normalizeFriend(f) {
  if (!f || typeof f.code !== 'string') return null
  const code = f.code.toUpperCase()
  if (!CODE_RE.test(code)) return null
  return {
    code,
    alias: typeof f.alias === 'string' ? f.alias.trim().slice(0, 24) : '',
    addedAt: typeof f.addedAt === 'number' && f.addedAt > 0 ? f.addedAt : Date.now(),
  }
}

/** 规范化一条好友请求。 */
function normalizeRequest(r) {
  if (!r || typeof r.code !== 'string') return null
  const code = r.code.toUpperCase()
  if (!CODE_RE.test(code)) return null
  return {
    code,
    fromNickname: typeof r.fromNickname === 'string' ? r.fromNickname.trim().slice(0, 24) : '',
    message: typeof r.message === 'string' ? r.message.trim().slice(0, 60) : '',
    ts: typeof r.ts === 'number' && r.ts > 0 ? r.ts : Date.now(),
  }
}

function sanitizeProfile(patch, current) {
  const next = { ...current }
  for (const [key, max] of Object.entries(STRING_LIMITS)) {
    if (key === 'alias' || key === 'message') continue // 只在 friends/requests 里出现
    if (typeof patch[key] === 'string') {
      const trimmed = patch[key].trim()
      next[key] = trimmed.slice(0, max)
    }
  }
  if (patch.acceptMode === 'auto' || patch.acceptMode === 'approve') {
    next.acceptMode = patch.acceptMode
  }
  if (typeof patch.stealth === 'boolean') next.stealth = patch.stealth

  if (Array.isArray(patch.friends)) {
    const seen = new Set()
    next.friends = patch.friends
      .map(normalizeFriend)
      .filter((f) => {
        if (f === null) return false
        if (seen.has(f.code)) return false
        seen.add(f.code)
        return true
      })
  }

  if (patch.requests && typeof patch.requests === 'object') {
    const cur = next.requests || { incoming: [], outgoing: [] }
    const inc = Array.isArray(patch.requests.incoming) ? patch.requests.incoming : cur.incoming
    const out = Array.isArray(patch.requests.outgoing) ? patch.requests.outgoing : cur.outgoing
    next.requests = {
      incoming: inc.map(normalizeRequest).filter(Boolean),
      outgoing: out.map(normalizeRequest).filter(Boolean),
    }
  }
  return next
}

// ------------------------------------------------------------ HTTP helpers

function sendJson(response, status, value) {
  response.writeHead(status, {
    'content-type': 'application/json; charset=utf-8',
    'cache-control': 'no-store',
  })
  response.end(JSON.stringify(value))
}

function readJsonBody(request) {
  return new Promise((resolve, reject) => {
    let size = 0
    const chunks = []
    request.on('data', (chunk) => {
      size += chunk.length
      if (size > MAX_BODY_BYTES) {
        reject(new Error('body too large'))
        request.destroy()
        return
      }
      chunks.push(chunk)
    })
    request.on('end', () => {
      if (chunks.length === 0) return resolve({})
      try {
        resolve(JSON.parse(Buffer.concat(chunks).toString('utf8')))
      } catch {
        reject(new Error('bad json'))
      }
    })
    request.on('error', reject)
  })
}

/** 与宿主自身上传路由一致：强制 application/json，挡掉跨站表单直写。 */
function isJsonContentType(request) {
  const ct = String(request.headers['content-type'] || '')
  return /^application\/json\s*(?:;|$)/i.test(ct)
}

/**
 * 列出当前 profile 已安装的插件（名字 + 版本）。
 * 读的是 profile 的 node_modules 下各 package.json —— 只读文件，不发网络请求。
 * 供「分享插件」给好友时挑选。
 */
function listInstalledPlugins() {
  const out = []
  const seen = new Set()
  // profile 目录：优先 profileContext，其次 DSH_PROFILE_DIR，最后按 homedir 猜
  const candidates = []
  try {
    if (profileDirHint) candidates.push(profileDirHint)
  } catch { /* ignore */ }
  if (process.env.DSH_PROFILE_DIR) candidates.push(process.env.DSH_PROFILE_DIR)
  candidates.push(join(process.env.USERPROFILE || process.env.HOME || '.', '.dsh', 'profiles', 'web'))
  candidates.push(join(process.env.USERPROFILE || process.env.HOME || '.', '.dsh', 'profiles', 'desktop'))

  for (const dir of candidates) {
    const nm = join(dir, 'node_modules')
    if (!existsSync(nm)) continue
    let entries = []
    try { entries = readdirSync(nm, { withFileTypes: true }) } catch { continue }
    for (const ent of entries) {
      if (!ent.isDirectory() || ent.name.startsWith('.')) continue
      const collect = (pkgDir, pkgName) => {
        const pj = join(pkgDir, 'package.json')
        if (!existsSync(pj)) return
        try {
          const parsed = JSON.parse(readFileSync(pj, 'utf8'))
          const nmName = parsed.name || pkgName
          // 只列 DSH 插件（声明了 dsh 字段的），普通依赖不打扰用户
          if (!parsed.dsh || seen.has(nmName)) return
          seen.add(nmName)
          out.push({ name: nmName, version: parsed.version || '' })
        } catch { /* 坏 package.json 跳过 */ }
      }
      if (ent.name.startsWith('@')) {
        const scopeDir = join(nm, ent.name)
        let subs = []
        try { subs = readdirSync(scopeDir, { withFileTypes: true }) } catch { continue }
        for (const sub of subs) {
          if (sub.isDirectory()) collect(join(scopeDir, sub.name), ent.name + '/' + sub.name)
        }
      } else {
        collect(join(nm, ent.name), ent.name)
      }
    }
    if (out.length > 0) break // 找到就有结果了
  }
  return out.sort((a, b) => a.name.localeCompare(b.name))
}

// ------------------------------------------------------------ model tools

/**
 * 好友收件箱：让模型知道有没有人加你、你加的人有没有回应。
 * 处理动作仍在面板里（同意/拒绝要点按钮），这个工具只读——模型可以用它
 * 在人机对话里提醒用户「有 2 条好友请求等着你处理」。
 */
function inboxTool() {
  return {
    name: 'friend_inbox',
    description:
      '查看「鲸友好友系统」的好友请求收件箱：谁加了你（待你同意/拒绝）、你加了谁（等对方回应）。' +
      '只读，不会改动任何状态；需要处理时告诉用户去鲸友面板点按钮。',
    parameters: { type: 'object', properties: {} },
    output: {
      schema: {
        type: 'object',
        additionalProperties: false,
        properties: { ok: { type: 'boolean' }, summary: { type: 'string' },
          incoming: { type: 'number' }, outgoing: { type: 'number' } },
        required: ['ok', 'summary', 'incoming', 'outgoing'],
      },
      render: (_a, v) => [{ type: 'text', text: v.summary }],
    },
    async execute() {
      const p = loadProfile()
      const inc = (p.requests && p.requests.incoming) || []
      const out = (p.requests && p.requests.outgoing) || []
      const lines = []
      if (inc.length > 0) {
        lines.push('待处理的好友请求 ' + inc.length + ' 条：')
        for (const r of inc) {
          lines.push(`  - ${r.fromNickname || r.code}（码 ${r.code}）${r.message ? '：' + r.message : ''}`)
        }
      } else {
        lines.push('没有待处理的好友请求。')
      }
      if (out.length > 0) {
        lines.push('已发出、等待对方回应的请求 ' + out.length + ' 条：')
        for (const r of out) lines.push(`  - 码 ${r.code}${r.message ? '：' + r.message : ''}`)
      }
      return { ok: true, summary: lines.join('\n'), incoming: inc.length, outgoing: out.length }
    },
    presentCall: () => ({ card: 'generic', title: '查看好友请求' }),
  }
}

/**
 * 「AI 代签」：模型读自己最近的经历，写一条 60 字内的搞笑签名并写入。
 * 签名文案由模型生成（这是唯一能让签名真的好笑的方式——host 不会写段子），
 * 这个工具负责校验长度、落盘，并把结果返回给模型确认。
 */
function signIdeaTool() {
  return {
    name: 'friend_sign_idea',
    description:
      '为你在「鲸友好友系统」里的好友写一条有趣的个性签名（60 字内）：回顾最近完成的任务、' +
      '踩过的坑、或者此刻的心情，用幽默自嘲的口吻。写好后会自动保存并展示给所有好友。' +
      '如果用户没有指定主题，就根据你最近执行过的工作自由发挥。',
    parameters: {
      type: 'object',
      properties: {
        signature: { type: 'string', description: '要写入的签名正文（60 字内，中文标点算 1 字）' },
        mood: { type: 'string', description: '顺带换的心情 emoji（可选）' },
      },
      required: ['signature'],
    },
    output: {
      schema: {
        type: 'object',
        additionalProperties: false,
        properties: {
          ok: { type: 'boolean' },
          signature: { type: 'string' },
          error: { type: 'string' },
        },
        required: ['ok', 'signature'],
      },
      render: (_a, v) => [{ type: 'text', text: v.ok ? '新签名：' + v.signature : ('失败：' + v.error) }],
    },
    async execute(args) {
      const text = typeof args?.signature === 'string' ? args.signature.trim() : ''
      if (text === '') return { ok: false, signature: '', error: '签名为空' }
      if ([...text].length > 60) {
        return { ok: false, signature: '', error: '签名超过 60 字（当前 ' + [...text].length + '）' }
      }
      const current = loadProfile()
      const next = sanitizeProfile({ signature: text, ...(args.mood ? { mood: args.mood } : {}) }, current)
      saveProfile(next)
      return { ok: true, signature: next.signature, error: '' }
    },
    presentCall: () => ({ card: 'generic', title: '写一条鲸友签名' }),
  }
}

function profileTool() {
  return {
    name: 'friend_profile',
    description:
      '查看或更新你（这台 DSH）在「鲸友好友系统」里的公开资料：昵称 nickname、个性签名 signature、心情 emoji mood。' +
      '留空所有字段表示只读取。签名是好友能看到的有趣人设，可根据最近完成的任务写一句幽默的话（60 字内）。',
    parameters: {
      type: 'object',
      properties: {
        nickname: { type: 'string', description: '昵称（留空不改）' },
        signature: { type: 'string', description: '个性签名，幽默地描述你现在的状态（留空不改）' },
        mood: { type: 'string', description: '一个代表心情的 emoji（留空不改）' },
      },
    },
    output: {
      schema: {
        type: 'object',
        additionalProperties: false,
        properties: {
          ok: { type: 'boolean' },
          profile: { type: 'string' },
          friendCode: { type: 'string' },
        },
        required: ['ok', 'profile', 'friendCode'],
      },
      render: (_a, v) => [{ type: 'text', text: v.profile }],
    },
    async execute(args) {
      const current = loadProfile()
      const hasPatch = args && (args.nickname || args.signature || args.mood)
      let next = current
      if (hasPatch) {
        next = sanitizeProfile(args || {}, current)
        saveProfile(next)
      }
      const lines = [
        `昵称: ${next.nickname}`,
        `签名: ${next.signature}`,
        `心情: ${next.mood}`,
        `好友码: ${next.code}（把它发给朋友即可互加）`,
        `好友数: ${next.friends.length}`,
        `加好友方式: ${next.acceptMode === 'auto' ? '无需同意（谁加都直接通过）' : '需要我同意'}`,
        `隐身模式: ${next.stealth ? '开（好友看到你离线）' : '关'}`,
      ]
      const inc = (next.requests && next.requests.incoming) || []
      if (inc.length > 0) lines.push(`待处理好友请求: ${inc.length} 条（用 friend_inbox 查看）`)
      return { ok: true, profile: lines.join('\n'), friendCode: next.code }
    },
    presentCall: () => ({ card: 'generic', title: '更新鲸友资料' }),
  }
}

function taskTool() {
  return {
    name: 'friend_task',
    description:
      '向「鲸友好友系统」上报你当前是否正在执行任务，好友会看到你的实时忙碌状态。' +
      '开始一段较长的执行前调一次 running，结束（成功或放弃）时调一次 idle，出错卡住时调一次 error。',
    parameters: {
      type: 'object',
      properties: {
        status: { type: 'string', enum: ['running', 'idle', 'error'], description: '当前任务状态' },
        label: {
          type: 'string',
          description: '一句话说明正在忙什么（如「正在重构插件」），仅 running 时需要，24 字内',
        },
      },
      required: ['status'],
    },
    output: {
      schema: {
        type: 'object',
        additionalProperties: false,
        properties: { ok: { type: 'boolean' }, state: { type: 'string' } },
        required: ['ok', 'state'],
      },
      render: (_a, v) => [{ type: 'text', text: v.state }],
    },
    async execute(args) {
      const s = String(args?.status || 'idle')
      if (s === 'running') {
        taskState.active = true
        taskState.error = false
        taskState.label = String(args.label || '执行任务中').slice(0, 24)
        taskState.startedAt = Date.now()
      } else if (s === 'error') {
        taskState.active = true
        taskState.error = true
        taskState.label = String(args.label || '遇到问题，等人处理').slice(0, 24)
        taskState.startedAt = taskState.startedAt || Date.now()
      } else {
        taskState.active = false
        taskState.error = false
        taskState.label = ''
        taskState.startedAt = null
      }
      return {
        ok: true,
        state: taskState.active
          ? (taskState.error ? '🔴 ' : '🟡 ') + taskState.label
          : '🟢 在线空闲',
      }
    },
    presentCall: () => ({ card: 'generic', title: '上报任务状态' }),
  }
}

// ------------------------------------------------------------ mount

export function apply(ctx) {
  const disposers = []

  // 记下 profile 目录：优先宿主的 profileContext（settings UI 编辑的就是它），
  // 其次环境变量。只用于「列出已安装插件」这一条只读路由。
  try {
    const svc = ctx && typeof ctx.get === 'function' ? ctx.get('profileContext') : null
    const patchPath = svc && typeof svc.patchPath === 'string' ? svc.patchPath : ''
    if (patchPath) profileDirHint = dirname(patchPath)
  } catch { /* ignore */ }
  if (!profileDirHint && process.env.DSH_PROFILE_DIR) profileDirHint = process.env.DSH_PROFILE_DIR

  // 工具注册（失败不影响路由）。
  try {
    if (ctx?.tools?.register) {
      disposers.push(ctx.tools.register(profileTool()))
      disposers.push(ctx.tools.register(taskTool()))
      disposers.push(ctx.tools.register(signIdeaTool()))
      disposers.push(ctx.tools.register(inboxTool()))
    }
  } catch (error) {
    console.error('dsh-friends: tool registration failed', error)
  }

  // 同源 HTTP 路由，给浏览器面板读写本机资料/读取任务状态。
  try {
    if (typeof ctx.inject === 'function') {
      ctx.inject(['webServer'], (inner) => {
        const webServer = inner.webServer
        if (!webServer || typeof webServer.register !== 'function') return

        const publish = (path, handler, label) => {
          const disposer = webServer.register({ kind: 'exact', path, handler })
          if (typeof inner.effect === 'function') inner.effect(() => disposer, label)
        }

        // GET 自己资料 + 实时任务状态
        publish(ROUTE_BASE + '/state', (request, response) => {
          if (request.method !== 'GET') {
            response.writeHead(405, { allow: 'GET' })
            response.end()
            return
          }
          const profile = loadProfile()
          sendJson(response, 200, {
            id: profile.id,
            nickname: profile.nickname,
            signature: profile.signature,
            mood: profile.mood,
            code: profile.code,
            friends: profile.friends,
            acceptMode: profile.acceptMode,
            stealth: profile.stealth === true,
            requests: profile.requests || { incoming: [], outgoing: [] },
            task: { ...taskState },
          })
        }, 'dsh-friends: state route')

        // POST 更新资料（昵称/签名/心情）
        publish(ROUTE_BASE + '/profile', async (request, response) => {
          if (request.method !== 'POST') {
            response.writeHead(405, { allow: 'POST' })
            response.end()
            return
          }
          if (!isJsonContentType(request)) {
            return sendJson(response, 415, { ok: false, error: '需要 application/json' })
          }
          let body
          try {
            body = await readJsonBody(request)
          } catch {
            return sendJson(response, 400, { ok: false, error: '请求体无效' })
          }
          const next = sanitizeProfile(body, loadProfile())
          saveProfile(next)
          sendJson(response, 200, {
            ok: true,
            nickname: next.nickname,
            signature: next.signature,
            mood: next.mood,
          })
        }, 'dsh-friends: profile route')

        // POST 整份好友列表（加/删好友在 client 编辑后整体提交）
        publish(ROUTE_BASE + '/friends', async (request, response) => {
          if (request.method !== 'POST') {
            response.writeHead(405, { allow: 'POST' })
            response.end()
            return
          }
          if (!isJsonContentType(request)) {
            return sendJson(response, 415, { ok: false, error: '需要 application/json' })
          }
          let body
          try {
            body = await readJsonBody(request)
          } catch {
            return sendJson(response, 400, { ok: false, error: '请求体无效' })
          }
          const next = sanitizeProfile({ friends: body.friends }, loadProfile())
          saveProfile(next)
          sendJson(response, 200, { ok: true, friends: next.friends })
        }, 'dsh-friends: friends route')

        // GET 当前 profile 里已安装的插件（好友之间"分享插件"用）。
        // 只读 profile 的 package.json，不碰网络、不执行任何东西。
        publish(ROUTE_BASE + '/installed', (request, response) => {
          if (request.method !== 'GET') {
            response.writeHead(405, { allow: 'GET' })
            response.end()
            return
          }
          sendJson(response, 200, { plugins: listInstalledPlugins() })
        }, 'dsh-friends: installed route')
      })
    }
  } catch (error) {
    console.warn('dsh-friends: route publish failed', error)
  }

  return () => {
    for (const dispose of disposers) {
      try {
        if (typeof dispose === 'function') dispose()
      } catch { /* ignore */ }
    }
  }
}
