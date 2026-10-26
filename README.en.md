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
| 🤝 Friend requests | Approval required by default; switch to auto-accept when you want anyone to get in |
| 🔗 Invite links | Generates `dsh-friends://add?code=…`; pasting it into the add box picks the code up |
| 📥 Request inbox | Pending requests (accept/reject) and sent requests (cancel), with an unread badge |
| ✎ Signature | Editable anytime, shown to all friends; the model can write one for you |
| 🐳 Mood emoji | One-tap mood, shown next to your signature |
| 👉 Poke | A floating emoji on your friend's whale; online only |
| 🏷 Aliases | Per-friend private nickname, edited inline with the pencil button |
| 🥷 Stealth mode | Stay online but broadcast nothing; friends see you offline |
| 🔐 End-to-end encrypted | AES-GCM-256 with a key derived from your friend code; relays see only ciphertext |
| 🚫 No signup | No accounts, no servers, no API keys — just a 6-digit friend code |

## 🚀 Install

```
dsh plugin --profile web add dsh-friends```

A `🐳 鲸友` entry appears in the DSH left rail.

## 🤝 Adding a friend

**By code**
1. Open the panel and copy your **6-digit friend code** (the `我的好友码` row)
2. Your friend hits `＋ 添加好友`, pastes it, and sends the request
3. You get a request (title badge + a card under `好友请求`) and click `同意`
4. You are friends, and presence/task status starts flowing

**By invite link**
- `加好友设置` → `邀请链接` → copy. The link looks like `dsh-friends://add?code=K7M2QX`; pasting it into the add box extracts the code automatically.

**Two approval modes** (in `加好友设置`)

| Mode | When someone adds you |
| --- | --- |
| **Needs my approval** (default) | You get a request, and nothing happens until you accept |
| **Auto-accept** | Anyone who enters your code becomes a friend immediately; you only get a notification |

> Auto-accept only changes how *others* add *you*; adding someone else still respects their setting.

## 🔒 Privacy

- The friend code **is** the shared secret: key = HKDF-SHA-256("dsh-friends/v1:" + code)
- Every message is AES-GCM with a fresh 12-byte IV; topics are guessable, payloads are not
- Broadcast content is only: nickname, signature, mood, status, task label, timestamp, plus friend requests and their note — never session content, files, or code
- Closing the page sends `bye`, so friends see you leave instantly
- Removing a friend notifies them (they drop you too); rejecting a request notifies nobody
- Auto-accept is a real trade-off: once your code is public, anyone can walk in. Stay on the default if unsure

## 🛠 Tech

- Zero-dependency client: hand-written MQTT 3.1.1 over WebSocket (CONNECT/SUBSCRIBE/PUBLISH/PING), no mqtt.js
- WebCrypto AES-GCM, no polyfills
- Multi-relay failover with concurrent probing (emqx / hivemq)
- Host side does local-only work: profile/request persistence, task-state scratchpad, model tools
- Tests: `npm test` (16 tests + browser render check)

## 🧰 Model tools

- `friend_profile` — read/update your nickname, signature, mood (also reports the current approval mode and stealth state)
- `friend_task` — report busy/idle/error so friends see it
- `friend_sign_idea` — have the model write a funny signature from your recent work (≤60 chars, auto-saved)
- `friend_inbox` — read the friend-request inbox (who added you, who you added); read-only

## ⚠️ Known limits

- Public relays are a free community service with no SLA; peak hours can be slow (multi-relay probing and reconnect are built in)
- Presence is broadcast every 8s, not millisecond-accurate
- Both sides need DSH (web or desktop) open to see each other
- A friend request can only be delivered while the other side is online; if they were offline the request stays local and is not auto-resent — just send it again
- Screenshots come from a render harness (real client.js + real React, themed through the host's own `data-ds-dark-theme` path), not an in-app capture

## 📄 License

MIT
