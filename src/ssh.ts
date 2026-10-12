import { Buffer } from 'buffer'
import {
  BaseStream,
  ChannelRequestMessage,
  SshAuthenticationType,
  SshClientSession,
  SshDisconnectReason,
  SshSessionConfiguration,
  type KeyPair,
  type SshChannel,
  type SshDataWriter,
} from '@microsoft/dev-tunnels-ssh'
import type { TcpSocket } from '@halone/sdk'
import { Curve25519Algorithm, Ed25519Algorithm } from './curve25519'

/** The SSH library's stream over a socket the shell opened. */
class SocketStream extends BaseStream {
  constructor(private readonly socket: TcpSocket) {
    super()
    socket.onData((bytes) => this.onData(Buffer.from(bytes)))
    socket.onClose((error) => (error ? this.onError(new Error(error)) : this.onEnd()))
  }

  async write(data: Buffer) {
    await this.socket.write(data)
  }

  async close(error?: Error) {
    await this.socket.close()
    if (!this.disposed) error ? this.onError(error) : this.onEnd()
  }
}

/** `pty-req` (RFC 4254 6.2): a terminal of [cols] by [rows], with no special modes. */
class PtyRequest extends ChannelRequestMessage {
  constructor(
    private readonly cols: number,
    private readonly rows: number,
  ) {
    super('pty-req', true)
  }

  protected onWrite(writer: SshDataWriter) {
    super.onWrite(writer)
    writer.writeString('xterm-256color', 'utf8')
    writer.writeUInt32(this.cols)
    writer.writeUInt32(this.rows)
    writer.writeUInt32(0)
    writer.writeUInt32(0)
    writer.writeBinary(Buffer.from([0]))
  }
}

/** `window-change` (RFC 4254 6.7). */
class WindowChange extends ChannelRequestMessage {
  constructor(
    private readonly cols: number,
    private readonly rows: number,
  ) {
    super('window-change', false)
  }

  protected onWrite(writer: SshDataWriter) {
    super.onWrite(writer)
    writer.writeUInt32(this.cols)
    writer.writeUInt32(this.rows)
    writer.writeUInt32(0)
    writer.writeUInt32(0)
  }
}

/** A host key as OpenSSH prints it: `SHA256:` and unpadded base64. */
export async function fingerprint(key: KeyPair): Promise<string> {
  const bytes = await key.getPublicKeyBytes()
  if (!bytes) throw new Error('the server sent no host key')
  const digest = new Uint8Array(await crypto.subtle.digest('SHA-256', new Uint8Array(bytes)))
  return 'SHA256:' + btoa(String.fromCharCode(...digest)).replace(/=+$/, '')
}

export interface Login {
  username: string
  password?: string
  key?: KeyPair
}

export interface Shell {
  write(text: string): void
  resize(cols: number, rows: number): void
  close(): Promise<void>
}

export interface ShellEvents {
  /** Decides whether to trust the server's host key; resolve false to stop. */
  checkHostKey(algorithm: string, fingerprint: string): Promise<boolean>
  onOutput(bytes: Uint8Array): void
  onClosed(reason: string | null): void
}

/** Connects over [socket], authenticates, and opens an interactive shell of [cols] by [rows]. */
export async function openShell(socket: TcpSocket, login: Login, cols: number, rows: number, events: ShellEvents): Promise<Shell> {
  const config = new SshSessionConfiguration()
  config.keyExchangeAlgorithms.unshift(new Curve25519Algorithm())
  config.publicKeyAlgorithms.unshift(new Ed25519Algorithm())
  const session = new SshClientSession(config)
  session.onAuthenticating((e) => {
    if (e.authenticationType !== SshAuthenticationType.serverPublicKey || !e.publicKey) return
    const key = e.publicKey
    e.authenticationPromise = fingerprint(key).then(async (print) => ((await events.checkHostKey(key.keyAlgorithmName, print)) ? {} : null))
  })
  let closed = false
  session.onClosed((e) => {
    if (closed) return
    closed = true
    events.onClosed(e.reason === SshDisconnectReason.byApplication ? null : (e.message ?? e.error?.message ?? 'disconnected'))
  })
  /** Ends the session with [message] as the reason the wearer sees, rather than the bare disconnect it causes. */
  async function fail(reason: SshDisconnectReason, message: string): Promise<never> {
    closed = true
    await session.close(reason).catch(() => {})
    throw new Error(message)
  }
  await session.connect(new SocketStream(socket))
  if (!(await session.authenticateServer())) await fail(SshDisconnectReason.hostKeyNotVerifiable, 'host key not trusted')
  const credentials = login.key ? { username: login.username, publicKeys: [login.key] } : { username: login.username, password: login.password }
  if (!(await session.authenticateClient(credentials))) {
    await fail(SshDisconnectReason.noMoreAuthMethodsAvailable, login.key ? 'the server did not accept this key' : 'wrong user name or password')
  }
  const channel: SshChannel = await session.openChannel()
  channel.onDataReceived((data) => {
    events.onOutput(new Uint8Array(data))
    channel.adjustWindow(data.length)
  })
  channel.onExtendedDataReceived((e) => {
    events.onOutput(new Uint8Array(e.data))
    channel.adjustWindow(e.data.length)
  })
  channel.onClosed(() => void session.close(SshDisconnectReason.byApplication))
  if (!(await channel.request(new PtyRequest(cols, rows)))) await fail(SshDisconnectReason.byApplication, 'the server refused a terminal')
  if (!(await channel.request(new ChannelRequestMessage('shell', true)))) await fail(SshDisconnectReason.byApplication, 'the server refused a shell')
  const encoder = new TextEncoder()
  return {
    write: (text) => void channel.send(Buffer.from(encoder.encode(text))).catch(() => {}),
    resize: (c, r) => void channel.request(new WindowChange(c, r)).catch(() => {}),
    close: async () => {
      closed = true
      await session.close(SshDisconnectReason.byApplication)
    },
  }
}
