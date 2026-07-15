import XCTest
@testable import AirliveCore

/// Stream-auth crypto tests.  Cross-implementation interop is pinned by a Known
/// Answer Test (KAT) shared with the out-of-repo receivers (Bridge / OBS plugin):
/// if `AirliveAuth.response` ever diverges from these bytes, the camera silently
/// stops authenticating against them, so pin it.  See docs/STREAM-AUTH-SPEC.md.
final class AuthTests: XCTestCase {

    /// The shared KAT — confirmed independently in CryptoKit (Bridge),
    /// CommonCrypto (OBS) and Python hmac.  Our tag must match bit-for-bit.
    func testHMACKnownAnswerVector() {
        let password = "airlive-test"                          // ASCII, UTF-8 key, no normalization
        let nonce    = Data((0..<32).map { UInt8($0) })        // 0x00 0x01 … 0x1f
        let expected = "f5708e4ebcf85a651f5f897323533dcf543add52d651179fbbd390124b1f4ab1"

        let tag = AirliveAuth.response(password: password, nonce: nonce)
        let hex = tag.map { String(format: "%02x", $0) }.joined()

        XCTAssertEqual(hex, expected, "AirliveAuth HMAC diverged from the shared interop KAT")
        XCTAssertEqual(tag.count, AirliveAuth.tagLength)        // 32 RAW bytes on the wire
    }

    /// verify() accepts the right tag, rejects a wrong password, and rejects a
    /// wrong-length tag without crashing.
    func testVerifyAcceptsAndRejects() {
        let password = "airlive-test"
        let nonce = AirliveAuth.makeNonce()
        let good  = AirliveAuth.response(password: password, nonce: nonce)

        XCTAssertTrue(AirliveAuth.verify(tag: good, password: password, nonce: nonce))
        XCTAssertFalse(AirliveAuth.verify(tag: good, password: "wrong", nonce: nonce))
        XCTAssertFalse(AirliveAuth.verify(tag: Data([1, 2, 3]), password: password, nonce: nonce))
    }

    /// Nonce is the right size and single-use (two draws must differ).
    func testNonceLengthAndUniqueness() {
        let a = AirliveAuth.makeNonce()
        let b = AirliveAuth.makeNonce()
        XCTAssertEqual(a.count, AirliveAuth.tagLength)
        XCTAssertNotEqual(a, b)
    }

    /// AuthResult JSON round-trips and matches the wire shape the receivers expect.
    func testAuthResultJSON() {
        XCTAssertEqual(String(data: AuthResult.success.encoded(), encoding: .utf8), "{\"ok\":true}")
        let fail = AuthResult.failure(.authFailed)
        let decoded = AuthResult.decode(from: fail.encoded())
        XCTAssertEqual(decoded?.ok, false)
        XCTAssertEqual(decoded?.reason, .authFailed)
    }
}
