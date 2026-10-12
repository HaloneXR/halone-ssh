import { Buffer } from 'buffer'
import { KeyExchangeService } from '@microsoft/dev-tunnels-ssh/services/keyExchangeService'
import {
  BigInt,
  KeyExchangeAlgorithm,
  SshSession,
  PublicKeyAlgorithm,
  SshDataReader,
  SshDataWriter,
  type KeyExchange,
  type KeyPair,
  type Signer,
  type Verifier,
} from '@microsoft/dev-tunnels-ssh'

/**
 * Ed25519 and X25519 for the SSH library, which predates them, on Web Crypto
 * (Chromium 137 and 133, so every WebView Halone runs on).
 */

const ED25519 = 'ssh-ed25519'
const SHA256_BYTES = 32

/** Web Crypto takes plain bytes, not the Buffers the SSH library hands around. */
const bytes = (data: Uint8Array) => new Uint8Array(data)

const wire = (...parts: Buffer[]) => {
  const writer = new SshDataWriter(Buffer.alloc(parts.reduce((sum, part) => sum + part.length + 4, 0)))
  parts.forEach((part) => writer.writeBinary(part))
  return writer.toBuffer()
}

/** An Ed25519 key: the public half always, the private half when it is ours. */
export class Ed25519KeyPair implements KeyPair {
  comment: string | null = null
  publicKey: CryptoKey | null = null
  privateKey: CryptoKey | null = null
  private raw: Buffer | null = null

  readonly keyAlgorithmName = ED25519

  get hasPublicKey() {
    return !!this.publicKey
  }

  get hasPrivateKey() {
    return !!this.privateKey
  }

  async generate() {
    const pair = (await crypto.subtle.generateKey({ name: 'Ed25519' }, true, ['sign', 'verify'])) as CryptoKeyPair
    this.privateKey = pair.privateKey
    await this.setRawPublicKey(Buffer.from(await crypto.subtle.exportKey('raw', pair.publicKey)))
  }

  /** From the 32-byte seed and public key that OpenSSH and JWK both carry. */
  async importRaw(seed: Uint8Array, publicKey: Uint8Array) {
    const b64url = (bytes: Uint8Array) => Buffer.from(bytes).toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '')
    const jwk = { kty: 'OKP', crv: 'Ed25519', x: b64url(publicKey), d: b64url(seed), ext: true }
    this.privateKey = await crypto.subtle.importKey('jwk', jwk, { name: 'Ed25519' }, true, ['sign'])
    await this.setRawPublicKey(Buffer.from(publicKey))
  }

  async exportJwk(): Promise<JsonWebKey> {
    if (!this.privateKey) throw new Error('no private key')
    return crypto.subtle.exportKey('jwk', this.privateKey)
  }

  private async setRawPublicKey(raw: Buffer) {
    this.raw = raw
    this.publicKey = await crypto.subtle.importKey('raw', bytes(raw), { name: 'Ed25519' }, true, ['verify'])
  }

  async setPublicKeyBytes(keyBytes: Buffer) {
    const reader = new SshDataReader(keyBytes)
    if (reader.readString('ascii') !== ED25519) throw new Error('not an Ed25519 key')
    await this.setRawPublicKey(reader.readBinary())
  }

  async getPublicKeyBytes(): Promise<Buffer | null> {
    return this.raw ? wire(Buffer.from(ED25519, 'ascii'), this.raw) : null
  }

  async importParameters(): Promise<void> {
    throw new Error('Ed25519 keys are imported with importRaw')
  }

  async exportParameters(): Promise<never> {
    throw new Error('Ed25519 keys are exported with exportJwk')
  }

  dispose() {}
}

class Ed25519SignerVerifier implements Signer, Verifier {
  readonly digestLength = 64

  constructor(private readonly key: Ed25519KeyPair) {}

  async sign(data: Buffer): Promise<Buffer> {
    if (!this.key.privateKey) throw new Error('no private key to sign with')
    return Buffer.from(await crypto.subtle.sign({ name: 'Ed25519' }, this.key.privateKey, bytes(data)))
  }

  async verify(data: Buffer, signature: Buffer): Promise<boolean> {
    if (!this.key.publicKey) throw new Error('no public key to verify with')
    return crypto.subtle.verify({ name: 'Ed25519' }, this.key.publicKey, bytes(signature), bytes(data))
  }

  dispose() {}
}

export class Ed25519Algorithm extends PublicKeyAlgorithm {
  constructor() {
    super(ED25519, ED25519, 'none')
  }

  createKeyPair(): KeyPair {
    return new Ed25519KeyPair()
  }

  async generateKeyPair(): Promise<KeyPair> {
    const key = new Ed25519KeyPair()
    await key.generate()
    return key
  }

  createSigner(keyPair: KeyPair): Signer {
    if (!(keyPair instanceof Ed25519KeyPair)) throw new TypeError('Ed25519 key pair expected')
    return new Ed25519SignerVerifier(keyPair)
  }

  createVerifier(keyPair: KeyPair): Verifier {
    if (!(keyPair instanceof Ed25519KeyPair)) throw new TypeError('Ed25519 key pair expected')
    return new Ed25519SignerVerifier(keyPair)
  }
}

/** `curve25519-sha256` (RFC 8731): X25519, with the shared secret read as a big-endian integer. */
class Curve25519Exchange implements KeyExchange {
  readonly digestLength = SHA256_BYTES
  private pair: CryptoKeyPair | null = null

  async startKeyExchange(): Promise<Buffer> {
    this.pair = (await crypto.subtle.generateKey({ name: 'X25519' }, true, ['deriveBits'])) as CryptoKeyPair
    return Buffer.from(await crypto.subtle.exportKey('raw', this.pair.publicKey))
  }

  async decryptKeyExchange(exchangeValue: Buffer): Promise<Buffer> {
    if (!this.pair) throw new Error('key exchange not started')
    const other = await crypto.subtle.importKey('raw', bytes(exchangeValue), { name: 'X25519' }, false, [])
    const secret = Buffer.from(await crypto.subtle.deriveBits({ name: 'X25519', public: other }, this.pair.privateKey, 256))
    return BigInt.fromBytes(secret, { unsigned: true }).toBytes()
  }

  async sign(data: Buffer): Promise<Buffer> {
    return Buffer.from(await crypto.subtle.digest('SHA-256', bytes(data)))
  }

  dispose() {}
}

export class Curve25519Algorithm extends KeyExchangeAlgorithm {
  constructor() {
    super('curve25519-sha256', 256, 'SHA2-256', SHA256_BYTES)
  }

  createKeyExchange(): KeyExchange {
    return new Curve25519Exchange()
  }
}

interface ExchangeHashContext {
  session: { isClientSession: boolean; remoteVersion?: { toString(): string } }
  exchangeContext: { clientKexInitPayload: Buffer; serverKexInitPayload: Buffer }
}

// The library hashes both sides' exchange values as mpints, which is right for
// its ECDH (whose points start with 0x04) but not for curve25519-sha256, where
// RFC 8731 makes them strings: a key whose first bit is set, or whose first
// byte is zero, then hashes differently from the server's and the host
// signature fails, three connections in four. Hash them as strings.
const service = KeyExchangeService.prototype as unknown as {
  computeExchangeHash(this: ExchangeHashContext, kex: KeyExchange, hostKey: Buffer, client: Buffer, server: Buffer, secret: Buffer): Promise<Buffer>
}
const libraryExchangeHash = service.computeExchangeHash
service.computeExchangeHash = async function (kex, hostKey, client, server, secret) {
  if (!(kex instanceof Curve25519Exchange)) return libraryExchangeHash.call(this, kex, hostKey, client, server, secret)
  const local = SshSession.localVersion.toString()
  const remote = this.session.remoteVersion?.toString() ?? ''
  const writer = new SshDataWriter(Buffer.alloc(2048))
  writer.writeString(this.session.isClientSession ? local : remote, 'ascii')
  writer.writeString(this.session.isClientSession ? remote : local, 'ascii')
  writer.writeBinary(this.exchangeContext.clientKexInitPayload)
  writer.writeBinary(this.exchangeContext.serverKexInitPayload)
  writer.writeBinary(hostKey)
  writer.writeBinary(client)
  writer.writeBinary(server)
  writer.writeBigInt(BigInt.fromBytes(secret, { unsigned: true }))
  return kex.sign(writer.toBuffer())
}
