// 渲染回归测试：在真实浏览器里加载 harness + client.js，断言面板真的渲染出来，
// 且渲染期没有任何 console.error / window.onerror。
//
// 这是 node smoke（只测模块契约）的补充：组件内部的未定义变量、坏 JSX 参数之类
// 只有真渲染才会暴露（曾在这里抓到过 `b is not defined`）。
//
// 依赖：ego-browser CLI（DSH 桌面 profile 自带）。找不到就跳过而非失败——
// 纯 node 环境（CI 无浏览器）仍能跑其余测试。
import { existsSync, copyFileSync, rmSync, writeFileSync } from 'node:fs'
import { fileURLToPath } from 'node:url'
import { dirname, join } from 'node:path'
import { execFileSync, execSync } from 'node:child_process'

const here = dirname(fileURLToPath(import.meta.url))
const pluginRoot = join(here, '..')

// harness 需要三份同目录文件：client.js（被测）、react.js / react-dom.js（UMD）。
// client.js 从 lib/ 复制，保证测的是当前源码；React UMD 首次从 npmmirror 拉一次并缓存。
try {
  copyFileSync(join(pluginRoot, 'lib', 'client.js'), join(here, 'client.js'))
} catch (e) {
  console.log('render-check: cannot stage client.js: ' + e.message)
  process.exit(1)
}
if (!existsSync(join(here, 'react.js'))) {
  const urls = [
    ['https://registry.npmmirror.com/react/18.3.1/files/umd/react.production.min.js', 'react.js'],
    ['https://registry.npmmirror.com/react-dom/18.3.1/files/umd/react-dom.production.min.js', 'react-dom.js'],
  ]
  try {
    for (const [u, f] of urls) {
      execSync(`powershell -NoProfile -Command "$ProgressPreference='SilentlyContinue'; Invoke-WebRequest -Uri '${u}' -OutFile '${join(here, f).replace(/\\/g, '/')}' -TimeoutSec 40"`, { stdio: 'ignore' })
    }
  } catch (e) {
    console.log('render-check: React UMD unavailable, SKIPPED (browser render check is optional)')
    process.exit(0)
  }
}

// ego-browser 入口（CDP 浏览器代理）
const CLI = process.platform === 'win32'
  ? 'C:/Users/zlwzk/.dsh/profiles/desktop/node_modules/dsh-browser-cdp/runtime/ego-linux/bin/ego-browser.mjs'
  : '/opt/ego-browser/bin/ego-browser.mjs'

if (!existsSync(CLI)) {
  console.log('render-check: ego-browser not found, SKIPPED (browser render check is optional)')
  process.exit(0)
}

// 探针脚本：导航到 harness，等待，读回面板状态。写成文件避免命令行转义地狱。
// 裸跑 ego-browser 没有 preamble（没有现成 page），所以这里先自行建 task space。
const probe = `
async function main() {
  let target = page
  if (!target) {
    const space = await taskSpaces.useOrCreate('dshf-render-check')
    target = space.page
  }
  if (!target) { console.log('RENDER_STATE_JSON:' + JSON.stringify({ fatal: 'no page facade' })); return }
  // theme=dark 让 harness 走宿主深色主题那条路径（body[data-ds-dark-theme]）
  await target.goto('file:///PLUGIN_ROOT/test/harness.html?theme=dark', { waitUntil: 'load', timeout: 30000 })
    .catch((e) => console.log('goto_err: ' + e.message))
  // 等面板首帧 + seed（seed 由 harness 每 250ms 灌一次在线状态）
  await new Promise((r) => setTimeout(r, 6000))
  const state = await target.evaluate(() => {
    const p = document.getElementById('panel')
    const logText = (document.getElementById('log') || {}).textContent || ''
    const store = window.__dshfStore
    const friends = store && store.state && store.state.friends
      ? Array.from(store.state.friends.values()).map((f) => ({ code: f.code, online: f.online, status: f.status, label: f.label }))
      : []
    return {
      panelChildren: p ? p.children.length : -1,
      panelLen: p && p.innerHTML ? p.innerHTML.length : -1,
      panelText: p && p.innerText ? p.innerText : '',
      log: logText,
      friends,
    }
  })
  console.log('RENDER_STATE_JSON:' + JSON.stringify(state))
  return state
}
await main()
`.replace(/PLUGIN_ROOT/g, pluginRoot.replace(/\\/g, '/'))

// ego-browser 从 stdin 读脚本（heredoc），不接受文件路径参数。
// Chrome 路径：优先 EGO_LINUX_CHROME（本机有 Chrome 就指过去）。
let stdout = ''
const childEnv = { ...process.env }
if (!childEnv.EGO_LINUX_CHROME) {
  for (const chrome of [
    'C:/Program Files/Google/Chrome/Application/chrome.exe',
    'C:/Program Files (x86)/Google/Chrome/Application/chrome.exe',
    'C:/Program Files/Microsoft/Edge/Application/msedge.exe',
    'C:/Program Files (x86)/Microsoft/Edge/Application/msedge.exe',
  ]) {
    if (existsSync(chrome)) { childEnv.EGO_LINUX_CHROME = chrome; break }
  }
}
try {
  stdout = execFileSync('node', [CLI], {
    input: probe,
    encoding: 'utf8',
    timeout: 90000,
    stdio: ['pipe', 'pipe', 'pipe'],
    env: childEnv,
  })
} catch (e) {
  const msg = String((e.stderr || '') + (e.message || ''))
  // 浏览器环境不可用（没装 Chrome、没有可附加的 tab、运行时未就绪）时跳过，
  // 这是一项可选的真机渲染验证——不该让它在无浏览器环境里把整套测试拖红。
  if (/no active tab|no Chrome|Chromium binary|ENOENT|timed out/i.test(msg)) {
    console.log('render-check: browser unavailable, SKIPPED (optional browser render check)')
    process.exit(0)
  }
  console.log('render-check FAILED to run: ' + (e.message || e))
  if (e.stdout) console.log('stdout: ' + String(e.stdout).slice(0, 2000))
  if (e.stderr) console.log('stderr: ' + String(e.stderr).slice(0, 2000))
  process.exit(1)
}

const m = /RENDER_STATE_JSON:(\{.*\})/.exec(stdout)
if (!m) {
  console.log('render-check FAILED: no state in output')
  console.log(stdout.slice(0, 2000))
  process.exit(1)
}
const state = JSON.parse(m[1])

const failures = []
if (state.panelLen < 500) failures.push('panel rendered almost nothing (len=' + state.panelLen + ')')
for (const must of ['鲸友', '小鲸测试机', 'K7M2QX', '我的好友码', '编辑资料', '加好友设置', '好友 · 4', '端到端加密']) {
  if (!state.panelText.includes(must)) failures.push('panel text missing: ' + must)
}
// 好友申请系统：待处理 + 已发出两块都要出现
for (const must of ['好友请求', '同意', '拒绝', '已发出的申请', '撤回']) {
  if (!state.panelText.includes(must)) failures.push('friend-request UI missing: ' + must)
}
// 好友码必须作为可见文本出现在面板里（曾经只是个小徽章，用户看不见）
const codeOccurrences = state.panelText.split('K7M2QX').length - 1
if (codeOccurrences < 1) failures.push('friend code not visible (occurrences=' + codeOccurrences + ')')
// 三种好友状态（在线/忙碌带任务名/错误带原因）都要能渲染出来
const onlineFriends = (state.friends || []).filter((f) => f.online)
if (onlineFriends.length < 3) {
  failures.push('seeded friends not online (got ' + onlineFriends.length + ': ' + JSON.stringify(state.friends) + ')')
}
for (const must of ['在线', '跑一个长任务', '构建挂了']) {
  if (!state.panelText.includes(must)) failures.push('friend state text missing: ' + must)
}
for (const must of ['apply OK', 'main seat: render() called']) {
  if (!state.log.includes(must)) failures.push('log missing: ' + must)
}
if (state.log.includes('console.error')) failures.push('render produced console.error (see log)')
if (state.log.includes('window.onerror')) failures.push('render produced window.onerror (see log)')
if (state.log.includes('apply FAILED')) failures.push('apply FAILED')

if (failures.length) {
  console.log('render-check FAILED:')
  for (const f of failures) console.log('  - ' + f)
  console.log('log: ' + state.log.slice(0, 1500))
  process.exit(1)
}
console.log('render-check OK (panel len=' + state.panelLen + ', no render errors)')
