# CyberCore Message Encryption

End-to-end encrypted private messages for Minecraft. `/msg` and `/r` are replaced by an encrypted
channel: messages are sealed on the sender's machine and opened on the recipient's, and the server
only ever relays ciphertext and the public keys players announce when they join. A server operator
reading the console, the logs or the database sees no message text — there is none to see.

It takes two parts, and both live in this repository on separate branches:

| Branch | What it is | Runs on |
| --- | --- | --- |
| [`26.1.2-fabric`](../../tree/26.1.2-fabric) | Client mod — does all encryption and decryption, owns the keys | Fabric client, Minecraft 26.1.2 |
| [`26.1.2-folia`](../../tree/26.1.2-folia) | Server plugin — relays sealed messages, verifies signatures, holds no key | Folia / Paper, Minecraft 26.1.2 |
| `main` | This README only | — |

The two sides share a wire protocol (`cybercore:encrypto`, currently version 3); the opcodes and
field order are mirrored in both branches and must stay in sync.

## How it works

- **Identity** — each client generates a long-term Ed25519 signing key and an X25519 exchange key.
  The private halves never leave the machine.
- **Handshake** — on join the client signs a server-issued nonce together with its public keys.
  The server records the keys and marks the session encrypted. A vanilla client never answers, and
  is then simply unable to send or receive private messages.
- **Sealing** — every message gets a fresh ephemeral X25519 key, an HKDF-SHA256 derived key and
  AES-256-GCM. Compromising a sender's identity key later does not decrypt earlier traffic.
- **Authenticity** — the sender signs the ciphertext with Ed25519. Both the relay and the recipient
  verify it, so the server cannot forge a message or reattribute one.
- **Key binding** — a player's exchange key is signed under their identity key, which stops the
  relay from handing out an exchange key of its own choosing.
- **Trust on first use** — the client pins each peer's identity fingerprint per server address. A
  hostile server can substitute keys, but not quietly: the pinned fingerprint changes and the client
  says so.

## Commands

Client-side, provided by the mod:

- `/msg <player> <message>`, plus `/tell`, `/w`, `/whisper`, `/m`
- `/r <message>`, `/reply <message>`
- `/encrypto status` — session state and your own fingerprint
- `/encrypto fingerprint <player>` — a peer's pinned fingerprint, for comparison out of band
- `/encrypto trust <player>` / `/encrypto forget <player>` — manage pins

Server-side:

- `/encrypto status`, `/encrypto list` — encryption state and key fingerprints of online players
  (permission `cybercore.encrypto.admin`)

## Server configuration

`config.yml` covers the handshake timeout, a per-player rate limit, the cooldown on prompting
players to install the mod, and every message the server sends, in MiniMessage format. There is no
placeholder for a message body anywhere in it: the server never holds one.

## Building

Both branches build with the bundled Gradle wrapper — `./gradlew build`. The client mod targets the
Fabric loader with Fabric API; the plugin targets the Folia API on Java 25.

## License

MIT.
