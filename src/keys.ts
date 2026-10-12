import { Buffer } from 'buffer'
import { SshDataReader, type KeyPair } from '@microsoft/dev-tunnels-ssh'
import { exportPrivateKey, importKey } from '@microsoft/dev-tunnels-ssh-keys'
import bcrypt from 'bcrypt-pbkdf'
import { Ed25519KeyPair } from './curve25519'

/** The key needs a passphrase, or the one given was wrong. */
export class PassphraseNeeded extends Error {
  constructor(readonly wrong: boolean) {
    super(wrong ? 'wrong passphrase' : 'this key is protected by a passphrase')
  }
}

const MAGIC = 'openssh-key-v1\0'

/** A fresh client key: Ed25519, what `ssh-keygen` makes by default. */
export async function makeKey(): Promise<KeyPair> {
  const key = new Ed25519KeyPair()
  await key.generate()
  return key
}

/** The key as this app keeps it: JSON for Ed25519, which the key library cannot write, PKCS#8 PEM for the rest. */
export async function storeKey(key: KeyPair): Promise<string> {
  if (key instanceof Ed25519KeyPair) return JSON.stringify({ type: 'ed25519', jwk: await key.exportJwk() })
  return exportPrivateKey(key)
}

export async function loadKey(stored: string): Promise<KeyPair> {
  if (!stored.trim().startsWith('{')) return importKey(stored)
  const { jwk } = JSON.parse(stored) as { jwk: JsonWebKey }
  const raw = (value: string) => Buffer.from(value.replace(/-/g, '+').replace(/_/g, '/'), 'base64')
  const key = new Ed25519KeyPair()
  await key.importRaw(raw(jwk.d!), raw(jwk.x!))
  return key
}

/** The line for `authorized_keys`. */
export async function publicKeyLine(key: KeyPair, comment: string): Promise<string> {
  const bytes = await key.getPublicKeyBytes()
  return `${key.keyAlgorithmName} ${bytes!.toString('base64')} ${comment}`
}

/**
 * A private key as pasted: OpenSSH's own format for Ed25519, plain or
 * passphrase-protected (bcrypt and AES-256-CTR, as `ssh-keygen` writes it),
 * and anything the key library reads for RSA and ECDSA.
 */
export async function importPrivateKey(text: string, passphrase?: string): Promise<KeyPair> {
  const body = text.match(/-----BEGIN OPENSSH PRIVATE KEY-----([\s\S]*?)-----END OPENSSH PRIVATE KEY-----/)?.[1]
  if (body) {
    const ed25519 = await readOpenSsh(Buffer.from(body.replace(/\s+/g, ''), 'base64'), passphrase)
    if (ed25519) return ed25519
  }
  return importKey(text, passphrase ?? null)
}

/** An OpenSSH key file's Ed25519 key, or null for another kind, which the key library reads. */
async function readOpenSsh(data: Buffer, passphrase?: string): Promise<KeyPair | null> {
  if (data.toString('latin1', 0, MAGIC.length) !== MAGIC) throw new Error('not an OpenSSH key')
  const reader = new SshDataReader(data.subarray(MAGIC.length))
  const cipher = reader.readString('ascii')
  const kdf = reader.readString('ascii')
  const kdfOptions = reader.readBinary()
  if (reader.readUInt32() !== 1) throw new Error('a file with several keys')
  const publicKey = new SshDataReader(reader.readBinary())
  if (publicKey.readString('ascii') !== 'ssh-ed25519') return null
  let secret = reader.readBinary()

  if (cipher !== 'none') {
    if (cipher !== 'aes256-ctr' || kdf !== 'bcrypt') throw new Error(`keys encrypted with ${cipher} are not supported`)
    if (!passphrase) throw new PassphraseNeeded(false)
    const options = new SshDataReader(kdfOptions)
    const salt = options.readBinary()
    const rounds = options.readUInt32()
    const derived = Buffer.alloc(48)
    const password = Buffer.from(passphrase, 'utf8')
    bcrypt.pbkdf(password, password.length, salt, salt.length, derived, derived.length, rounds)
    const aes = await crypto.subtle.importKey('raw', new Uint8Array(derived.subarray(0, 32)), 'AES-CTR', false, ['decrypt'])
    const counter = new Uint8Array(derived.subarray(32, 48))
    secret = Buffer.from(await crypto.subtle.decrypt({ name: 'AES-CTR', counter, length: 128 }, aes, new Uint8Array(secret)))
  }

  const keys = new SshDataReader(secret)
  if (keys.readUInt32() !== keys.readUInt32()) throw new PassphraseNeeded(true)
  keys.readString('ascii')
  const pub = keys.readBinary()
  const priv = keys.readBinary()
  const key = new Ed25519KeyPair()
  await key.importRaw(priv.subarray(0, 32), pub)
  key.comment = keys.readString('utf8') || null
  return key
}
