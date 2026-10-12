# Halone SSH

An SSH client for [Halone](https://github.com/HaloneXR/halone): terminal
sessions in tabs, over the shell's TCP sockets, with password and key
(Ed25519, RSA, ECDSA) authentication. Vue and xterm.js.

## Building

```sh
git clone git@github.com:HaloneXR/halone-ssh.git
cd halone-ssh
pnpm install
pnpm dev          # run it in Halone from this machine, while developer mode is on
pnpm run pack     # build dev.halone.ssh-<version>.halone
```

## License

[MIT](LICENSE).
