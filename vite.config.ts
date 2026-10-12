import { createRequire } from 'node:module'
import { fileURLToPath } from 'node:url'
import { defineConfig } from 'vite'
import vue from '@vitejs/plugin-vue'

const require = createRequire(import.meta.url)

export default defineConfig({
  plugins: [vue()],
  define: { global: 'globalThis' },
  resolve: {
    alias: {
      // The SSH library's Node code path, never taken in a page.
      'node-rsa': fileURLToPath(new URL('./src/stubs/empty.ts', import.meta.url)),
      // Its channel streams are Node Duplex streams. Absolute, so the library's own folder finds it.
      stream: require.resolve('stream-browserify'),
      events: require.resolve('events/'),
    },
  },
  build: { chunkSizeWarningLimit: 1000 },
})
