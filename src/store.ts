import { ref, watch } from 'vue'

export interface Host {
  id: string
  label: string
  host: string
  port: number
  username: string
  auth: 'key' | 'password'
}

export interface KnownHost {
  algorithm: string
  fingerprint: string
}

function stored<T>(key: string, fallback: T) {
  let initial = fallback
  try {
    const text = localStorage.getItem(key)
    if (text) initial = JSON.parse(text) as T
  } catch {
    initial = fallback
  }
  const value = ref(initial)
  watch(value, (next) => localStorage.setItem(key, JSON.stringify(next)), { deep: true })
  return value
}

/** Everything stays in this app's own origin, which no other app or site can read. */
export const hosts = stored<Host[]>('hosts', [])
export const knownHosts = stored<Record<string, KnownHost>>('knownHosts', {})
/** The client key, PKCS#8 PEM. Passwords are never kept. */
export const privateKey = stored<string | null>('privateKey', null)

export const hostKeyId = (host: Host) => `${host.host}:${host.port}`
