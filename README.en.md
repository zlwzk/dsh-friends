# 🐳 dsh-friends — DSH Whale Friends

See your fellow DeepSeek Harness users: **are they online, are they running a task, what are they busy with** — plus a playful signature and a poke.

This isn't "is my friend around", it's "**is their AI around and busy**" — a human/AI hybrid social layer.

## 📸 Screenshots

| Dark | Light |
| --- | --- |
| ![dark](assets/screenshots/panel-dark.png) | ![light](assets/screenshots/panel-light.png) |

---

## ✨ Features

| Feature | Notes |
| --- | --- |
| 🟢 Live presence | Open DSH = visible; close it = gone. 8s heartbeat, offline after 3 missed beats |
| 🟡 Task status | Turns "busy" while the model runs a task, with what it's doing |
| 🔴 Error alert | A stuck/failed task shows red on the friend's side so you can help |
| ✎ Signature | Editable anytime, shown to all friends; the model can write one for you |
| 🐳 Mood emoji | One-tap mood, shown next to your signature |
| 👉 Poke | A floating emoji on your friend's whale; online only |
| 🔐 End-to-end encrypted | AES-GCM-256 with a key derived from your friend code; relays see only ciphertext |
| 🚫 No signup | No accounts, no servers, no API keys — just a 6-digit friend code |

## 🚀 Install

```
dsh plugin --profile web add dsh-friends```

A `🐳 鲸友` entry appears in the DSH left rail.

## 🤝 Adding a friend

1. Open the whale panel, copy your **6-digit friend code**, send it to a friend
2. They hit `＋ 添加好友` and enter your code
3. You enter theirs
4. Both sides immediately see each other's presence and task status

## 🔒 Privacy

- The friend code **is** the shared secret: key = HKDF-SHA-256("dsh-friends/v1:" + code)
- Every message is AES-GCM with a fresh 12-byte IV; topics are guessable, payloads are not
- Broadcast content is only: nickname, signature, mood, status, task label, timestamp — never session content, files, or code
- Closing the page sends `bye`, so friends see you leave instantly

## 🛠 Tech

- Zero-dependency client: hand-written MQTT 3.1.1 over WebSocket (CONNECT/SUBSCRIBE/PUBLISH/PING), no mqtt.js
- WebCrypto AES-GCM, no polyfills
- Multi-relay failover with concurrent probing (emqx / hivemq)
- Host side does three local things only: profile persistence, task-state scratchpad, model tools
- Tests: `npm test` (12 tests)

## 🧰 Model tools

- `friend_profile` — read/update your nickname, signature, mood
- `friend_task` — report busy/idle/error so friends see it
- `friend_sign_idea` — have the model write a funny signature from your recent work (≤60 chars, auto-saved)

## ⚠️ Known limits

- Public relays are a free community service with no SLA; peak hours can be slow (multi-relay probing and reconnect are built in)
- Presence is broadcast every 8s, not millisecond-accurate
- Both sides need DSH (web or desktop) open to see each other
- Screenshots come from a render harness (real client.js + real React, themed through the host's own `data-ds-dark-theme` path), not an in-app capture

## 📄 License

MIT
