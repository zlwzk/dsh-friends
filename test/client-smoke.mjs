// 在 node 里模拟 DSH 的 window.__ModuleLoader__，加载 client.js 验证模块契约。
import { readFileSync } from 'node:fs'
import { fileURLToPath } from 'node:url'
import { dirname, join } from 'node:path'
import assert from 'node:assert'

const here = dirname(fileURLToPath(import.meta.url))
const code = readFileSync(join(here, '..', 'lib', 'client.js'), 'utf8')

// 最小假环境
const registry = {}
globalThis.window = {
  __ModuleLoader__: {
    load({ id, factory }) {
      // factory 是同步的；react 由 DSH webview 内置提供，这里用同步 shim 代替。
      const reactShim = makeReactShim()
      const syncRequire = (name) => {
        if (name === 'react') return reactShim
        throw new Error('unexpected require ' + name)
      }
      registry[id] = factory(syncRequire)
    },
  },
  addEventListener() {},
  removeEventListener() {},
}
globalThis.document = {
  createElement: () => ({ style: {}, dataset: {}, appendChild() {}, remove() {} }),
  head: { appendChild() {} },
}
// node24 全局 crypto 只读且已是 webcrypto，无需赋值
globalThis.WebSocket = function () { throw new Error('should not connect during module eval') }
globalThis.btoa = (s) => Buffer.from(s, 'binary').toString('base64')
globalThis.atob = (s) => Buffer.from(s, 'base64').toString('binary')
globalThis.TextEncoder = TextEncoder
globalThis.TextDecoder = TextDecoder
globalThis.fetch = async () => { throw new Error('no fetch during eval') }
globalThis.setInterval = () => 0
globalThis.clearInterval = () => {}
globalThis.setTimeout = (fn) => 0
globalThis.clearTimeout = () => {}
globalThis.confirm = () => false

// 极简 React shim：createElement 返回普通对象，供 apply() 注册时引用组件
function makeReactShim() {
  function createElement(type, props, ...children) { return { type, props, children } }
  return { createElement, default: undefined }
}

// 执行 client.js（它顶层调用 window.__ModuleLoader__.load）
// eslint-disable-next-line no-eval
(new Function(code)).call(globalThis)

const mod = registry['dsh-friends']
assert.ok(mod, 'module registered under id dsh-friends')
assert.equal(typeof mod.apply, 'function', 'exports apply()')
assert.ok(Array.isArray(mod.inject) && mod.inject.includes('slots'), 'injects slots')
assert.equal(mod.name, 'dsh-friends', 'exports name')

// 调 apply，给一个假 slots ctx，确认注册两个 seat 不抛
const registered = []
const fakeCtx = {
  effect(fn) { try { fn() } catch (e) {} },
  slots: {
    inject(slot, cb) { return cb() },
    register(descriptor, Component) { registered.push({ descriptor, Component }); return () => {} },
  },
}
mod.apply(fakeCtx)

const seats = registered.map((r) => r.descriptor.name + '#' + (r.descriptor.id || r.descriptor.key))
assert.ok(seats.includes('main#dsh-friends'), 'main panel seat registered: ' + seats.join(','))
assert.ok(seats.includes('sidebar.panellist#dsh-friends'), 'rail seat registered: ' + seats.join(','))
for (const r of registered) {
  assert.equal(typeof r.Component, 'function', 'seat gets a component')
}

console.log('client smoke OK; seats =', seats.join(', '))
