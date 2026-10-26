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
const probe = `
async function main() {
  await page.goto('file:///PLUGIN_ROOT/test/harness.html', { waitUntil: 'load', timeout: 30000 })
    .catch((e) => console.log('goto_err: ' + e.message))
  await new Promise((r) => setTimeout(r, 3500))
  const state = await page.evaluate(() => {
    const p = document.getElementById('panel')
    const logText = (document.getElementById('log') || {}).textContent || ''
    return {
      panelChildren: p ? p.children.length : -1,
      panelLen: p && p.innerHTML ? p.innerHTML.length : -1,
      panelText: p && p.innerText ? p.innerText.slice(0, 1200) : '',
      log: logText,
    }
  })
  console.log('RENDER_STATE_JSON:' + JSON.stringify(state))
  return state
}
await main()
`.replace(/PLUGIN_ROOT/g, pluginRoot.replace(/\\/g, '/'))

// ego-browser 从 stdin 读脚本（heredoc），不接受文件路径参数。
let stdout = ''
try {
  stdout = execFileSync('node', [CLI], {
    input: probe,
    encoding: 'utf8',
    timeout: 90000,
    stdio: ['pipe', 'pipe', 'pipe'],
  })
} catch (e) {
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
for (const must of ['鲸友', '小鲸测试机', 'K7M2QX', '编辑资料', '添加好友', '好友 · 3', '端到端加密']) {
  if (!state.panelText.includes(must)) failures.push('panel text missing: ' + must)
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
