<script setup lang="ts">
import { nextTick, onBeforeUnmount, onMounted, ref, watch } from 'vue'
import { Terminal } from '@xterm/xterm'
import { FitAddon } from '@xterm/addon-fit'
import { useHalone } from '@halone/sdk'
import { openShell, type Login, type Shell } from './ssh'
import type { Host } from './store'

const props = defineProps<{
  host: Host
  login: Login
  active: boolean
  checkHostKey: (host: Host, algorithm: string, fingerprint: string) => Promise<boolean>
}>()
const emit = defineEmits<{ connected: []; closed: [reason: string | null] }>()

const halone = useHalone()
const element = ref<HTMLElement>()
const status = ref<'connecting' | 'open'>('connecting')
const terminal = new Terminal({
  fontSize: 20,
  fontFamily: 'ui-monospace, "SF Mono", Menlo, "DejaVu Sans Mono", monospace',
  cursorBlink: true,
  theme: { background: '#000000', foreground: '#e8ecf4' },
})
const fit = new FitAddon()
terminal.loadAddon(fit)
let shell: Shell | null = null
let ended = false
const resizes = new ResizeObserver(() => props.active && fit.fit())

function end(reason: string | null) {
  if (ended) return
  ended = true
  emit('closed', reason)
}

onMounted(async () => {
  terminal.open(element.value!)
  fit.fit()
  terminal.onData((data) => shell?.write(data))
  terminal.onResize(({ cols, rows }) => shell?.resize(cols, rows))
  resizes.observe(element.value!)
  terminal.focus()
  try {
    const socket = await halone.sockets.connect(props.host.host, props.host.port, { timeoutMs: 15_000 })
    shell = await openShell(socket, props.login, terminal.cols, terminal.rows, {
      checkHostKey: (algorithm, fingerprint) => props.checkHostKey(props.host, algorithm, fingerprint),
      onOutput: (bytes) => terminal.write(bytes),
      onClosed: (reason) => end(reason),
    })
    if (ended) return void shell.close()
    status.value = 'open'
    emit('connected')
  } catch (error) {
    end(error instanceof Error ? error.message : String(error))
  }
})

watch(
  () => props.active,
  async (active) => {
    if (!active) return
    await nextTick()
    fit.fit()
    terminal.focus()
  },
)

onBeforeUnmount(() => {
  ended = true
  resizes.disconnect()
  void shell?.close()
  terminal.dispose()
})

defineExpose({
  disconnect: () => (shell ? shell.close().then(() => end(null)) : end(null)),
  focus: () => terminal.focus(),
})
</script>

<template>
  <div class="session">
    <p v-if="status === 'connecting'" class="connecting">Connecting to {{ host.host }}…</p>
    <div ref="element" class="terminal" />
  </div>
</template>

<style scoped>
.session {
  position: relative;
  height: 100%;
  padding: 6px;
}
.terminal {
  height: 100%;
}
.connecting {
  position: absolute;
  left: 16px;
  top: 8px;
  margin: 0;
  color: #8d98b3;
}
</style>
