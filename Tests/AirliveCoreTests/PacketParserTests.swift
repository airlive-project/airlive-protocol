import XCTest
@testable import AirliveCore

/// Wire-format framing tests for `PacketParser` — the one piece of the
/// protocol whose failures (partial TCP reads, mid-stream desync) are
/// field-only and miserable to reproduce live.  Device-free.
final class PacketParserTests: XCTestCase {

    private func sample(_ ts: Int64, _ bytes: [UInt8]) -> AirlivePacket {
        AirlivePacket(type: .sample, timestampMicros: ts, payload: Data(bytes))
    }

    // MARK: Round-trips

    func testSinglePacketRoundTrip() {
        let p = sample(123_456, [1, 2, 3, 4, 5])
        let out = PacketParser().append(p.encode())
        XCTAssertEqual(out.count, 1)
        XCTAssertEqual(out[0].type, .sample)
        XCTAssertEqual(out[0].timestampMicros, 123_456)
        XCTAssertEqual(out[0].payload, Data([1, 2, 3, 4, 5]))
    }

    func testEmptyPayloadPacket() {
        // formatDescription / a keyframe-less unit can be zero-length;
        // total == headerSize must still parse.
        let p = AirlivePacket(type: .formatDescription, timestampMicros: 0, payload: Data())
        let out = PacketParser().append(p.encode())
        XCTAssertEqual(out.count, 1)
        XCTAssertEqual(out[0].type, .formatDescription)
        XCTAssertTrue(out[0].payload.isEmpty)
    }

    func testTwoPacketsInOneAppend() {
        var data = sample(1, [10]).encode()
        data.append(sample(2, [20, 21]).encode())
        let out = PacketParser().append(data)
        XCTAssertEqual(out.count, 2)
        XCTAssertEqual(out[0].timestampMicros, 1)
        XCTAssertEqual(out[1].timestampMicros, 2)
        XCTAssertEqual(out[1].payload, Data([20, 21]))
    }

    // MARK: Partial TCP reads (the reason a stateful parser exists)

    func testPayloadSplitAcrossTwoAppends() {
        let p = sample(7, [1, 2, 3, 4, 5, 6, 7, 8])
        let encoded = p.encode()
        let parser = PacketParser()
        // First chunk: header + first 3 payload bytes → nothing complete yet.
        let cut = AirlivePacket.headerSize + 3
        XCTAssertEqual(parser.append(encoded.prefix(cut)).count, 0)
        // Remainder completes the packet.
        let out = parser.append(encoded.suffix(from: encoded.startIndex.advanced(by: cut)))
        XCTAssertEqual(out.count, 1)
        XCTAssertEqual(out[0].payload, Data([1, 2, 3, 4, 5, 6, 7, 8]))
    }

    func testHeaderSplitAcrossAppends() {
        let p = sample(9, [42])
        let encoded = p.encode()
        let parser = PacketParser()
        // Only 5 header bytes so far → can't even read the header.
        XCTAssertEqual(parser.append(encoded.prefix(5)).count, 0)
        let out = parser.append(encoded.suffix(from: encoded.startIndex.advanced(by: 5)))
        XCTAssertEqual(out.count, 1)
        XCTAssertEqual(out[0].payload, Data([42]))
    }

    func testByteAtATimeDelivery() {
        let p = sample(11, [1, 2, 3])
        let encoded = p.encode()
        let parser = PacketParser()
        var got: [AirlivePacket] = []
        for byte in encoded { got += parser.append(Data([byte])) }
        XCTAssertEqual(got.count, 1)
        XCTAssertEqual(got[0].payload, Data([1, 2, 3]))
    }

    // MARK: Resync

    func testResyncAfterLeadingGarbage() {
        // Garbage bytes (no ARLV magic) precede a valid packet — the parser
        // drops one byte at a time until the magic aligns, then recovers it.
        var data = Data([0xFF, 0xEE, 0xDD])
        data.append(sample(5, [9, 9, 9]).encode())
        let out = PacketParser().append(data)
        XCTAssertEqual(out.count, 1)
        XCTAssertEqual(out[0].timestampMicros, 5)
        XCTAssertEqual(out[0].payload, Data([9, 9, 9]))
    }

    func testStreamOfManyPacketsInArbitraryChunks() {
        let parser = PacketParser()
        var expected: [Int64] = []
        var wire = Data()
        for i in 0..<50 {
            expected.append(Int64(i))
            wire.append(sample(Int64(i), [UInt8(i % 256), UInt8((i * 3) % 256)]).encode())
        }
        // Feed in irregular 13-byte chunks (smaller than the 17-byte header).
        var got: [AirlivePacket] = []
        var idx = wire.startIndex
        while idx < wire.endIndex {
            let end = wire.index(idx, offsetBy: 13, limitedBy: wire.endIndex) ?? wire.endIndex
            got += parser.append(Data(wire[idx..<end]))
            idx = end
        }
        XCTAssertEqual(got.map(\.timestampMicros), expected)
    }

    // MARK: Protocol hardening (version + length cap)

    private func rawHeader(version: UInt8, type: UInt8, length: UInt32, ts: Int64) -> Data {
        var d = Data()
        var m = AirlivePacket.magic.bigEndian
        d.append(contentsOf: withUnsafeBytes(of: &m) { Data($0) })
        d.append(version)
        d.append(type)
        var l = length.bigEndian
        d.append(contentsOf: withUnsafeBytes(of: &l) { Data($0) })
        var t = ts.bigEndian
        d.append(contentsOf: withUnsafeBytes(of: &t) { Data($0) })
        return d
    }

    func testRejectsOversizedLengthAndResyncs() {
        // A header with a 4 GB length must NOT wedge the parser waiting for
        // bytes that never come — it resyncs and recovers the next valid one.
        var data = rawHeader(version: AirlivePacket.protocolVersion,
                             type: AirlivePacket.PacketType.sample.rawValue,
                             length: 0xFFFF_FFFF, ts: 0)
        data.append(sample(7, [1, 2, 3]).encode())
        let out = PacketParser().append(data)
        XCTAssertEqual(out.count, 1)
        XCTAssertEqual(out[0].payload, Data([1, 2, 3]))
    }

    func testRejectsVersionMismatchAndResyncs() {
        // A packet stamped with a different protocol version is dropped
        // (incompatible peer) and the parser recovers the next valid packet
        // rather than mis-framing the mismatched one.
        var data = sample(5, [9, 9, 9]).encode()
        data[4] = 0x99                          // corrupt the version byte
        data.append(sample(6, [7, 7]).encode())
        let out = PacketParser().append(data)
        XCTAssertEqual(out.count, 1)
        XCTAssertEqual(out[0].timestampMicros, 6)
        XCTAssertEqual(out[0].payload, Data([7, 7]))
    }

    func testHeaderCarriesProtocolVersion() {
        let encoded = sample(1, [0]).encode()
        XCTAssertEqual(encoded[4], AirlivePacket.protocolVersion)
        XCTAssertEqual(encoded.count, AirlivePacket.headerSize + 1)
    }

    // MARK: Forward-compat — unknown packet types (PROTOCOL-COMPAT-SPEC §3)

    func testUnknownTypeSkipsWholePacketNotByteByByte() {
        // A NEWER peer's packet type (200) with a valid header must be skipped
        // WHOLE (headerSize+length), NOT resynced one byte at a time.  Proof:
        // embed a COMPLETE valid packet inside the unknown packet's payload —
        // byte-by-byte resync would find that decoy's magic and wrongly emit it;
        // skip-whole steps clean over it.
        let decoy = sample(999, [0xAA, 0xBB]).encode()   // a valid packet, hidden inside
        var unknown = rawHeader(version: AirlivePacket.protocolVersion,
                                type: 200,
                                length: UInt32(decoy.count), ts: 0)
        unknown.append(decoy)
        var data = unknown
        data.append(sample(7, [1, 2, 3]).encode())       // the real trailing packet
        let out = PacketParser().append(data)
        XCTAssertEqual(out.count, 1, "the embedded decoy must NOT surface")
        XCTAssertEqual(out[0].timestampMicros, 7)
        XCTAssertEqual(out[0].payload, Data([1, 2, 3]))
    }

    func testUnknownTypeWaitsForWholePacketBeforeSkipping() {
        // The unknown packet arrives SPLIT: header + partial payload must not be
        // dropped early (that would desync a genuinely-partial read) — the parser
        // waits, then skips the whole thing once complete and recovers the next
        // valid packet.
        let payloadLen = 10
        var unknown = rawHeader(version: AirlivePacket.protocolVersion,
                                type: 201,
                                length: UInt32(payloadLen), ts: 0)
        unknown.append(Data(repeating: 0x5A, count: payloadLen))
        let parser = PacketParser()
        let cut = AirlivePacket.headerSize + 4   // header + 4 of 10 payload bytes
        XCTAssertEqual(parser.append(unknown.prefix(cut)).count, 0)
        var rest = Data(unknown.suffix(from: unknown.startIndex.advanced(by: cut)))
        rest.append(sample(8, [4, 4]).encode())
        let out = parser.append(rest)
        XCTAssertEqual(out.count, 1)
        XCTAssertEqual(out[0].timestampMicros, 8)
        XCTAssertEqual(out[0].payload, Data([4, 4]))
    }

    // The 2× maxPayloadLength overflow backstop in append() is DELIBERATELY
    // unreachable through the public API (every `break` leaves at most one
    // max-size packet ≈ header + 16 MB < 32 MB buffered) — it guards a FUTURE
    // parser edit, so there is no honest test that drives it without pathological
    // internal setup.  Not tested by design (no coverage theater).
}
