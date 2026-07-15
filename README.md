<div align="center">
  <img src=".github/logo.png" width="130" alt="Airlive Protocol">
  <h1>Airlive Protocol</h1>
  <p><b>The open wire protocol behind Airlive Camera — build your own receiver.</b></p>

  <a href="LICENSE"><img src="https://img.shields.io/badge/License-Apache_2.0-blue.svg" alt="License: Apache 2.0"></a>
  <img src="https://img.shields.io/badge/Swift-5.9%2B-orange" alt="Swift 5.9+">
  <img src="https://img.shields.io/badge/Language--agnostic-wire%20spec-lightgrey" alt="Language-agnostic wire spec">
</div>

---

**Airlive Camera** (iPhone) streams live video to a receiver over the LAN and
accepts remote camera control back. This repository is the **open specification**
of that link — the byte layout, the discovery mechanism, the control messages and
the optional authentication — plus a reference implementation in Swift
(`AirliveCore`).

The **camera app is proprietary**; the **protocol is open**. Anyone can build a
receiver — open-source or commercial — that speaks it. The Apache-2.0 license
imposes no copyleft: use it in a closed product, sell it, whatever you need.

Existing receivers that speak this protocol:
[**Airlive Bridge**](https://github.com/airlive-project/airlive-bridge) (Mac
multicam switcher) and the
[**Airlive for OBS**](https://github.com/airlive-project/airlive-for-obs) plugin —
both open-source working references.

## At a glance

- **Transport:** a single **TCP** connection, full-duplex.
- **Discovery:** Bonjour / mDNS service type **`_airlive._tcp`**. The receiver
  advertises; the camera connects to the one the operator picks.
- **Video:** fixed **H.264, 1080p, AVCC** — a cool, low-latency, universally
  decodable proxy of the operator's viewfinder. (The camera's local recording
  codec — HEVC/ProRes — is independent and never changes the wire.)
- **Control:** JSON messages on the *same* socket — a full state snapshot from
  the camera, single set-commands from the receiver (ISO, WB, lens, focus, tally…).
- **Auth:** optional, off by default — an HMAC challenge-response that proves the
  peer knows a shared receiver password. No TLS (the LAN video isn't secret; this
  is access control, not confidentiality).

## Frame format

Every message on the socket is one framed packet:

```
┌────────┬─────────┬────────┬──────────────────┬──────────────────────┬──────────┐
│ 4 B    │ 1 B     │ 1 B    │ 4 B              │ 8 B                  │ N B      │
│ magic  │ version │ type   │ payload_length   │ timestamp_us         │ payload  │
│ "ARLV" │ 1       │ 0..5   │ big-endian u32   │ big-endian i64       │          │
└────────┴─────────┴────────┴──────────────────┴──────────────────────┴──────────┘
   0x41 0x52 0x4C 0x56                          (microseconds)
```

- **Header is 18 bytes**, all multi-byte fields **big-endian**.
- `magic` = `0x41524C56` (`"ARLV"`). A parser that loses sync scans forward
  byte-by-byte until it finds the next magic.
- `version` = `1`. A byte was reserved after `magic` so a newer receiver detects
  an incompatible framing epoch and resyncs past it instead of mis-framing bytes
  as video. It has **never** been bumped — v1 framing + H.264 1080p is the
  permanent baseline every peer supports.
- `payload_length` is capped at **16 MiB**; a header claiming more is treated as
  corrupt (resync). TCP delivers a byte stream — one `recv` is **not** one packet;
  a parser must buffer and frame. See `PacketParser` for a correct, tested
  implementation (partial reads, resync, forward-skip of unknown types).

### Packet types

| `type` | Name | Direction | Payload |
|:---:|---|---|---|
| `0` | `formatDescription` | camera → receiver | H.264 decoder init (parameter sets). Sent **once** at stream start. |
| `1` | `sample` | camera → receiver | One encoded H.264 access unit (AVCC length-prefixed NALUs). |
| `2` | `control` | both | UTF-8 **JSON** `ControlMessage` (see below). |
| `3` | `authChallenge` | receiver → camera | 32-byte single-use random nonce. |
| `4` | `authResponse` | camera → receiver | 32-byte `HMAC-SHA256(password, nonce)` tag. |
| `5` | `authResult` | receiver → camera | JSON `AuthResult` (`ok`, or `fail` + reason). |

A receiver that gets a **valid** header with an **unknown** type (a newer peer)
must skip the *whole* packet (`header + payload_length`), not one byte — new
types are always gated on the `hello` handshake, so this is just the safety net.

## Connection lifecycle

```
receiver advertises _airlive._tcp
        │
camera connects (TCP)
        │
  ── optional auth (only if the receiver requires a password) ──
  receiver → authChallenge (nonce)
  camera   → authResponse  (HMAC-SHA256(password, nonce))
  receiver → authResult    (ok / fail); on fail it closes the socket
        │
camera → control: { "type": "hello", ... }     (who/what/caps)
receiver → control: { "type": "hello", ... }
        │
camera → control: { "type": "state", ... }     (full StateSnapshot)
camera → formatDescription                      (decoder init, once)
camera → sample, sample, sample …               (video)
        │
receiver → control: { "type": "setISO", "floatValue": 400 }   (any time)
camera   → control: { "type": "state", ... }    (re-broadcast after any change)
```

The handshake runs **once**, before any video, so it adds zero per-frame cost.

## Control channel (JSON)

`control` packets carry a `ControlMessage` — a small discriminated union keyed by
`type`. Only the matching value field is read; unknown keys are ignored (so the
protocol extends additively without breaking older peers).

**Camera → receiver — `state`:** a full `StateSnapshot` sent on connect and after
every change (including auto-exposure/auto-WB readback). It carries the live
values (iso, shutter, wb, lens, zoom, focus, fps, colour space, LUT, tally/remote
gates, rotation hint) **and** a `capabilities` object with this exact device's
ranges/options (iso/shutter/wb bounds, fps/resolution/codec/colour-space lists) so
a controller renders device-accurate sliders instead of guessing.

**Receiver → camera — set-commands**, e.g.:

| `type` | Value field | Meaning |
|---|---|---|
| `setISO` / `setShutter` / `setWB` / `setTint` | `floatValue` | Manual exposure / white balance |
| `setLens` | `stringValue` | Switch lens (`"0.5x"`, `"1x"`, `"2x"`…) |
| `setZoom` / `setFocusPosition` | `floatValue` | Zoom factor / focus distance |
| `setFocusPoint` / `setExposurePoint` | `pointX`,`pointY` | Tap-to-focus / -expose (normalised, sensor-landscape space) |
| `setFPS` | `intValue` | Frame rate |
| `setResolution` / `setColorSpace` | `stringValue` | Reconfigure (refused mid-take) |
| `setLUT` | `lutName`,`boolValue` | Preview LUT name + on/off |
| `setExposureAuto` / `setWhiteBalanceAuto` / `setFocusAuto` | `boolValue` | Auto toggles |
| `setStabilization` | `stringValue` | `"Off"` / `"Standard"` / `"High"` |
| `setCue` | `stringValue` | Tally: `"none"` / `"preview"` / `"program"` |
| `setDeliveryMode` | `stringValue` | `"videoAndControl"` or `"controlOnly"` (encoder off) |

The **camera is the source of truth**: it applies a command, then re-broadcasts a
`state` so every controller re-syncs. An old camera that doesn't know a verb just
ignores it — a safe degrade the receiver detects from the unchanged `state`.

## Authentication (optional)

Off by default. When the receiver has a password set, it challenges every new
connection **before** any video:

- The **password never crosses the wire** — only an HMAC of a one-time nonce.
- Tag = `HMAC-SHA256(key = password UTF-8 bytes, message = raw 32-byte nonce)`,
  a raw 32-byte tag (no hex/base64 on the wire).
- The nonce is single-use, so a captured response can't be replayed.
- Verification is constant-time.

Replicate `AirliveAuth` **exactly** (UTF-8 key, raw-byte message, SHA-256, raw
tag) or the handshake won't interoperate. See [`Auth.swift`](Sources/AirliveCore/Auth.swift).

## Using the Swift package

```swift
// Package.swift
dependencies: [
    .package(url: "https://github.com/airlive-project/airlive-protocol.git", from: "1.0.0")
]
```

```swift
import AirliveCore

let parser = PacketParser()                 // stateful — feed it raw TCP bytes
for packet in parser.append(bytesFromSocket) {
    switch packet.type {
    case .formatDescription: setUpDecoder(packet.payload)
    case .sample:            decode(packet.payload, at: packet.timestampMicros)
    case .control:           handle(ControlMessage.decode(from: packet.payload))
    default:                 break          // auth handled at connect
    }
}

// Send a command back on the same socket:
socket.send(ControlMessage.setISO(400).encodeAsPacket().encode())
```

`AirliveCore` depends only on **Foundation** and **CryptoKit** (Apple platforms).
On a non-Apple platform, implement the framing from the spec above — it is
deliberately trivial (an 18-byte big-endian header + JSON) so a receiver in C,
Python, Rust or JS is a small amount of code.

## Building a non-Apple receiver — checklist

1. Advertise `_airlive._tcp` over mDNS; accept a TCP connection.
2. If you require a password, run the auth handshake (types 3→4→5) first.
3. Read framed packets (18-byte header, buffer for partial reads, resync on bad
   magic/version, skip unknown types whole).
4. On `formatDescription` (0), init your H.264 decoder from the parameter sets;
   on `sample` (1), decode AVCC access units.
5. Parse `control` (2) JSON for `state`; send set-commands as `control` packets.

The **Airlive for OBS** plugin is a working reference of exactly this in C++/FFmpeg.

## License

**Apache-2.0** — see [`LICENSE`](LICENSE) and [`NOTICE`](NOTICE). Permissive: use
it in open-source or closed commercial receivers, no copyleft. The license covers
the code; it doesn't grant use of the "Airlive" name or logo.
