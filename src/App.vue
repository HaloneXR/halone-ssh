<script setup lang="ts">
import { computed, nextTick, ref, shallowRef, watch } from 'vue'
import '@xterm/xterm/css/xterm.css'
import type { KeyPair } from '@microsoft/dev-tunnels-ssh'
import { useHalone } from '@halone/sdk'
import Session from './Session.vue'
import { importPrivateKey, loadKey, makeKey, PassphraseNeeded, publicKeyLine, storeKey } from './keys'
import type { Login } from './ssh'
import { hostKeyId, hosts, knownHosts, privateKey, type Host } from './store'

const halone = useHalone()

interface Tab {
  id: number
  host: Host
  login: Login
}

const tabs = ref<Tab[]>([])
/** The open tab: a session's id, or null for the host list. */
const current = ref<number | null>(null)
const sessions = shallowRef(new Map<number, InstanceType<typeof Session>>())
let nextTab = 1

const editing = ref<Host | null>(null)
const message = ref<string | null>(null)
const publicKey = ref<string | null>(null)
const keyType = ref<string | null>(null)
const confirmReplace = ref(false)
const importing = ref(false)
const pasted = ref('')
const passphrase = ref('')
const needsPassphrase = ref(false)

/** What the app is waiting on the wearer for while connecting. */
const asking = ref<
  | { kind: 'password'; host: Host; resolve: (password: string | null) => void }
  | { kind: 'host-key'; host: Host; algorithm: string; fingerprint: string; changed: boolean; resolve: (trust: boolean) => void }
  | null
>(null)
const password = ref('')

async function currentKey(): Promise<KeyPair | null> {
  return privateKey.value ? loadKey(privateKey.value) : null
}

async function showPublicKey() {
  const key = await currentKey().catch(() => null)
  publicKey.value = key ? await publicKeyLine(key, 'halone-ssh') : null
  keyType.value = key?.keyAlgorithmName ?? null
}
void showPublicKey()

async function newKey() {
  if (privateKey.value && !confirmReplace.value) {
    confirmReplace.value = true
    return
  }
  confirmReplace.value = false
  privateKey.value = await storeKey(await makeKey())
  await showPublicKey()
}

async function saveImported() {
  try {
    const key = await importPrivateKey(pasted.value.trim(), needsPassphrase.value ? passphrase.value : undefined)
    privateKey.value = await storeKey(key)
    pasted.value = ''
    passphrase.value = ''
    needsPassphrase.value = false
    importing.value = false
    message.value = null
    await showPublicKey()
  } catch (error) {
    if (error instanceof PassphraseNeeded) {
      needsPassphrase.value = true
      message.value = error.wrong ? 'That passphrase is wrong.' : 'This key is protected: enter its passphrase.'
      return
    }
    message.value = `That key could not be read (${error instanceof Error ? error.message : error}).`
  }
}

function copyPublicKey() {
  if (publicKey.value) halone.clipboard.writeText(publicKey.value).then(() => (message.value = 'Public key copied.'), () => {})
}

function newHost() {
  editing.value = { id: crypto.randomUUID(), label: '', host: '', port: 22, username: '', auth: privateKey.value ? 'key' : 'password' }
}

function saveHost() {
  const host = editing.value
  if (!host || !host.host.trim() || !host.username.trim()) return
  host.host = host.host.trim()
  host.username = host.username.trim()
  host.label = host.label.trim() || `${host.username}@${host.host}`
  const index = hosts.value.findIndex((h) => h.id === host.id)
  if (index >= 0) hosts.value[index] = host
  else hosts.value.push(host)
  editing.value = null
}

function removeHost(host: Host) {
  hosts.value = hosts.value.filter((h) => h.id !== host.id)
}

function askPassword(host: Host) {
  return new Promise<string | null>((resolve) => (asking.value = { kind: 'password', host, resolve }))
}

function askHostKey(host: Host, algorithm: string, fingerprint: string, changed: boolean) {
  return new Promise<boolean>((resolve) => (asking.value = { kind: 'host-key', host, algorithm, fingerprint, changed, resolve }))
}

async function checkHostKey(host: Host, algorithm: string, fingerprint: string) {
  const known = knownHosts.value[hostKeyId(host)]
  if (known?.algorithm === algorithm && known.fingerprint === fingerprint) return true
  const trust = await askHostKey(host, algorithm, fingerprint, !!known)
  asking.value = null
  if (trust) knownHosts.value[hostKeyId(host)] = { algorithm, fingerprint }
  return trust
}

async function connect(host: Host) {
  message.value = null
  let login: Login
  if (host.auth === 'key') {
    const key = await currentKey()
    if (!key) {
      message.value = 'This host signs in with a key, and there is none yet: make one below.'
      return
    }
    login = { username: host.username, key }
  } else {
    password.value = ''
    const typed = await askPassword(host)
    asking.value = null
    if (typed === null) return
    login = { username: host.username, password: typed }
  }
  const tab = { id: nextTab++, host, login }
  tabs.value.push(tab)
  current.value = tab.id
}

/** A session ended: its tab goes, and the host list comes back, with the reason if it failed. */
function closed(tab: Tab, reason: string | null) {
  tabs.value = tabs.value.filter((t) => t.id !== tab.id)
  sessions.value.delete(tab.id)
  if (reason) message.value = `${tab.host.username}@${tab.host.host}: ${reason}`
  if (current.value === tab.id) current.value = null
}

/** Shows a tab; a session's terminal takes the keyboard, which clicking the tab took from it. */
async function select(id: number | null) {
  current.value = id
  if (id === null) return
  await nextTick()
  sessions.value.get(id)?.focus()
}

function register(id: number, session: unknown) {
  if (session) sessions.value.set(id, session as InstanceType<typeof Session>)
}

const tabTitle = (tab: Tab) => `${tab.host.username}@${tab.host.host}`
const active = computed(() => tabs.value.find((t) => t.id === current.value) ?? null)

watch(active, (tab) => halone.windows.setTitle(tab ? `SSH — ${tabTitle(tab)}` : 'SSH').catch(() => {}))
</script>

<template>
  <nav class="tabs">
    <button class="tab" :class="{ current: current === null }" @click="select(null)">Hosts</button>
    <div v-for="tab in tabs" :key="tab.id" class="tab" :class="{ current: current === tab.id }" @click="select(tab.id)">
      <span>{{ tabTitle(tab) }}</span>
      <button class="close" :aria-label="`Disconnect ${tabTitle(tab)}`" @click.stop="sessions.get(tab.id)?.disconnect()">×</button>
    </div>
  </nav>

  <main v-show="current === null" class="hosts">
    <p v-if="message" class="message">{{ message }}</p>

    <section>
      <div v-for="host in hosts" :key="host.id" class="host">
        <div class="host-text">
          <strong>{{ host.label }}</strong>
          <span class="muted">{{ host.username }}@{{ host.host }}{{ host.port === 22 ? '' : `:${host.port}` }} · {{ host.auth === 'key' ? 'key' : 'password' }}</span>
        </div>
        <button class="primary" @click="connect(host)">Connect</button>
        <button @click="editing = { ...host }">Edit</button>
        <button @click="removeHost(host)">Delete</button>
      </div>
      <p v-if="!hosts.length" class="muted">No hosts yet. Termux on this phone: run <code>sshd</code> there, then add localhost, port 8022.</p>
      <button v-if="!editing" @click="newHost">Add host</button>
    </section>

    <form v-if="editing" class="editor" @submit.prevent="saveHost">
      <label>Name <input v-model="editing.label" placeholder="optional" /></label>
      <label>Host <input v-model="editing.host" required autocapitalize="off" spellcheck="false" /></label>
      <label>Port <input v-model.number="editing.port" type="number" min="1" max="65535" /></label>
      <label>User <input v-model="editing.username" required autocapitalize="off" spellcheck="false" /></label>
      <label>
        Sign in with
        <select v-model="editing.auth">
          <option value="key">this app's key</option>
          <option value="password">a password, asked each time</option>
        </select>
      </label>
      <div class="row">
        <button type="submit" class="primary">Save</button>
        <button type="button" @click="editing = null">Cancel</button>
      </div>
    </form>

    <section class="key">
      <h2>Your key</h2>
      <template v-if="publicKey">
        <p class="muted">Add this line to <code>~/.ssh/authorized_keys</code> on each host that signs in with a key.</p>
        <code class="public-key">{{ publicKey }}</code>
        <div class="row">
          <button @click="copyPublicKey">Copy public key</button>
          <button @click="newKey">{{ confirmReplace ? 'Really replace it? Hosts using it stop working' : 'Make a new key' }}</button>
          <button @click="importing = !importing">Import a key</button>
        </div>
      </template>
      <div v-else class="row">
        <button class="primary" @click="newKey">Make a key</button>
        <button @click="importing = !importing">Import a key</button>
      </div>
      <form v-if="importing" class="editor" @submit.prevent="saveImported">
        <textarea v-model="pasted" rows="6" placeholder="-----BEGIN OPENSSH PRIVATE KEY-----" spellcheck="false" />
        <input v-if="needsPassphrase" v-model="passphrase" type="password" placeholder="Passphrase" />
        <p class="muted">Ed25519, ECDSA and RSA keys, as <code>ssh-keygen</code> writes them.</p>
        <div class="row">
          <button type="submit" class="primary">Use this key</button>
          <button type="button" @click="importing = false">Cancel</button>
        </div>
      </form>
    </section>
  </main>

  <div v-for="tab in tabs" v-show="current === tab.id" :key="tab.id" class="pane">
    <Session
      :ref="(session) => register(tab.id, session)"
      :host="tab.host"
      :login="tab.login"
      :active="current === tab.id"
      :check-host-key="checkHostKey"
      @closed="(reason) => closed(tab, reason)"
    />
  </div>

  <div v-if="asking" class="scrim">
    <form v-if="asking.kind === 'password'" class="dialog" @submit.prevent="asking.resolve(password)">
      <h2>Password for {{ asking.host.username }}@{{ asking.host.host }}</h2>
      <input v-model="password" type="password" autofocus />
      <div class="row">
        <button type="button" @click="asking.resolve(null)">Cancel</button>
        <button type="submit" class="primary">Connect</button>
      </div>
    </form>
    <div v-else class="dialog" :class="{ danger: asking.changed }">
      <h2>{{ asking.changed ? 'The host key has changed' : 'New host' }}</h2>
      <p v-if="asking.changed">
        {{ asking.host.host }} identifies itself differently from last time. That happens when the server is reinstalled, or when someone is
        in the way. Connect only if you know why.
      </p>
      <p v-else>First connection to {{ asking.host.host }}. Its {{ asking.algorithm }} key is:</p>
      <code>{{ asking.fingerprint }}</code>
      <div class="row">
        <button @click="asking.resolve(false)">Cancel</button>
        <button :class="asking.changed ? 'danger' : 'primary'" @click="asking.resolve(true)">
          {{ asking.changed ? 'Trust the new key' : 'Trust and connect' }}
        </button>
      </div>
    </div>
  </div>
</template>

<style>
* {
  box-sizing: border-box;
}
html,
body,
#app {
  height: 100%;
  margin: 0;
  background: #000;
  color: #e8ecf4;
  font: 20px system-ui, sans-serif;
}
button,
input,
select,
textarea {
  font: inherit;
  color: inherit;
}
button {
  padding: 10px 18px;
  border: 0;
  border-radius: 12px;
  background: #222a3d;
  cursor: pointer;
}
button.primary {
  background: #3a63d8;
}
button.danger {
  background: #b3363a;
}
input,
select,
textarea {
  width: 100%;
  padding: 10px 14px;
  border: 1px solid #333c52;
  border-radius: 10px;
  background: #0d1018;
}
code {
  font-family: ui-monospace, Menlo, monospace;
  font-size: 17px;
}
.muted {
  color: #8d98b3;
}
.row {
  display: flex;
  flex-wrap: wrap;
  gap: 10px;
  margin-top: 12px;
}
#app {
  display: flex;
  flex-direction: column;
}
.tabs {
  flex: none;
  display: flex;
  gap: 6px;
  padding: 8px 10px;
  background: #0f1420;
  overflow-x: auto;
}
.tab {
  flex: none;
  display: flex;
  align-items: center;
  gap: 6px;
  padding: 8px 14px;
  border-radius: 10px;
  background: transparent;
  color: #8d98b3;
  cursor: pointer;
  white-space: nowrap;
}
.tab.current {
  background: #222a3d;
  color: #e8ecf4;
}
.tab .close {
  padding: 0 6px;
  background: transparent;
  font-size: 22px;
  line-height: 1;
}
.hosts {
  flex: 1;
  min-height: 0;
  overflow-y: auto;
  padding: 20px 32px;
}
.pane {
  flex: 1;
  min-height: 0;
}
h2 {
  margin: 0 0 10px;
  font-size: 22px;
}
section {
  margin-bottom: 28px;
}
.message {
  padding: 10px 14px;
  border-radius: 10px;
  background: #24304d;
}
.host {
  display: flex;
  align-items: center;
  gap: 10px;
  padding: 12px 14px;
  margin-bottom: 8px;
  border-radius: 14px;
  background: #0f1420;
}
.host-text {
  flex: 1;
  display: flex;
  flex-direction: column;
}
.editor {
  display: grid;
  gap: 10px;
  max-width: 640px;
  margin-bottom: 20px;
}
.editor label {
  display: grid;
  gap: 4px;
  color: #8d98b3;
}
.public-key {
  display: block;
  padding: 10px 14px;
  border-radius: 10px;
  background: #0d1018;
  overflow-wrap: anywhere;
}
.scrim {
  position: fixed;
  inset: 0;
  display: grid;
  place-items: center;
  background: rgba(0, 0, 0, 0.7);
}
.dialog {
  width: min(640px, 90vw);
  padding: 24px;
  border-radius: 18px;
  background: #151b2a;
}
.dialog.danger {
  border: 2px solid #b3363a;
}
.dialog code {
  display: block;
  padding: 10px;
  border-radius: 8px;
  background: #0d1018;
  overflow-wrap: anywhere;
}
</style>
