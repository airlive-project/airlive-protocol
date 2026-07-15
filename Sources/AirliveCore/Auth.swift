import Foundation
import CryptoKit

// MARK: - Receiver-password authentication (challenge-response, HMAC)

/// Why this file exists: the camera, Airlive Studio, the Bridge and the OBS
/// plugin are FOUR separate codebases that must compute the same auth tag bit-
/// for-bit, or the handshake won't interoperate.  The one canonical definition
/// of "what gets HMAC'd and how" lives here so the in-repo apps share it
/// literally; the out-of-repo receivers (Bridge / OBS) replicate exactly this.
///
/// Threat model (deliberately narrow — see ROADMAP "Stream auth"):
///   The LAN stream is NOT secret — anyone on the network can already watch the
///   open video, and that's acceptable for this product class.  The single real
///   threat is a same-LAN prankster running the app who occupies a channel slot
///   or injects a fake/spoofed feed into someone's multiview.  That is an ACCESS
///   problem, not a confidentiality one, so there is deliberately NO TLS (it buys
///   nothing here and costs thermal budget).  We only prove "the peer connecting
///   is one of ours."
///
/// Properties:
///   • The password NEVER crosses the wire — only an HMAC of a one-time nonce.
///   • The nonce is single-use → a captured response can't be replayed.
///   • Exactly ONE HMAC per connection, BEFORE any video; nothing per frame, so
///     it adds zero load to the stream hot path (no thermal impact).
public enum AirliveAuth {

    /// Bytes in a response tag — SHA-256 output size.
    public static let tagLength = 32
    /// Bytes in a challenge nonce.  Equal to `tagLength` today, but named
    /// separately so the camera's nonce-size guard documents intent and survives
    /// a future nonce-size change without silently breaking.
    public static let nonceLength = 32

    /// A fresh single-use random nonce for an `authChallenge` (RECEIVER side).
    /// Uses the system CSPRNG; the `SystemRandomNumberGenerator` fallback is also
    /// cryptographically secure on Apple platforms, so a nonce is never weak.
    public static func makeNonce() -> Data {
        var bytes = [UInt8](repeating: 0, count: nonceLength)
        if SecRandomCopyBytes(kSecRandomDefault, nonceLength, &bytes) != errSecSuccess {
            var rng = SystemRandomNumberGenerator()
            for i in bytes.indices { bytes[i] = .random(in: .min ... .max, using: &rng) }
        }
        return Data(bytes)
    }

    /// THE canonical response tag (CAMERA side): `HMAC-SHA256` with
    /// key = the password's UTF-8 bytes, message = the raw nonce → 32 bytes.
    /// Out-of-repo receivers must replicate exactly this (UTF-8 key, raw-byte
    /// message, SHA-256, raw 32-byte tag — no hex/base64 on the wire).
    public static func response(password: String, nonce: Data) -> Data {
        let key = SymmetricKey(data: Data(password.utf8))
        return Data(HMAC<SHA256>.authenticationCode(for: nonce, using: key))
    }

    /// Verify a response (RECEIVER side).  `isValidAuthenticationCode` is
    /// CONSTANT-TIME, so a wrong tag leaks no timing signal an attacker could
    /// use to recover the expected value byte-by-byte.
    public static func verify(tag: Data, password: String, nonce: Data) -> Bool {
        let key = SymmetricKey(data: Data(password.utf8))
        return HMAC<SHA256>.isValidAuthenticationCode(tag, authenticating: nonce, using: key)
    }
}

/// Why a receiver rejected (or could not start) an authenticated connection.
/// Wire value is the snake_case `rawValue` inside the `AuthResult` JSON.
public enum AuthReason: String, Codable, Sendable {
    /// The receiver requires a password but the camera sent no/blank response
    /// (e.g. nothing cached yet) — the camera should PROMPT for a password.
    case authRequired = "auth_required"
    /// The HMAC didn't match — wrong password.  The camera should clear any
    /// cached password for this receiver and prompt again.
    case authFailed   = "auth_failed"
}

/// Result of the handshake, sent receiver → camera as the `authResult` packet
/// (JSON).  `ok == true` → proceed to `formatDescription` / `sample`; otherwise
/// the receiver closes the connection with a clean FIN right after sending this.
public struct AuthResult: Codable, Sendable {
    public var ok: Bool
    public var reason: AuthReason?

    public init(ok: Bool, reason: AuthReason? = nil) {
        self.ok = ok
        self.reason = reason
    }

    public static let success = AuthResult(ok: true)
    public static func failure(_ reason: AuthReason) -> AuthResult {
        AuthResult(ok: false, reason: reason)
    }

    public func encoded() -> Data {
        // Loud-fail (mirrors ControlMessage.encodeAsPacket): a silent empty
        // payload can't decode, so a peer would neither authorize nor reject —
        // a silent stall in a security path.  This struct is all value types, so
        // encoding never realistically fails; log if it ever does.
        do { return try JSONEncoder().encode(self) }
        catch { print("[AuthResult] ❌ encode failed: \(error)"); return Data() }
    }
    public static func decode(from data: Data) -> AuthResult? {
        try? JSONDecoder().decode(AuthResult.self, from: data)
    }
}
