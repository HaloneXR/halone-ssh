import { Buffer } from 'buffer'

// The SSH library and the stream polyfill it needs are written for Node:
// they read a global Buffer and process as they load, and defer with nextTick.
const scope = globalThis as { Buffer?: typeof Buffer; process?: unknown }
scope.Buffer ??= Buffer
scope.process ??= {
  env: {},
  versions: {},
  browser: true,
  nextTick: (callback: (...args: unknown[]) => void, ...args: unknown[]) => queueMicrotask(() => callback(...args)),
}
