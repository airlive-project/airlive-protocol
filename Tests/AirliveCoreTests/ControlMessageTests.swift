import XCTest
@testable import AirliveCore

/// Round-trip tests for the JSON control channel — the camera↔studio
/// remote-control contract.  A silent encode/decode break here means
/// "the knob doesn't move" with no error, so pin it.
final class ControlMessageTests: XCTestCase {

    /// Encode a control message as a packet, push it through the parser,
    /// and decode it back — the full wire path both apps actually use.
    private func roundTrip(_ msg: ControlMessage) -> ControlMessage? {
        let wire = msg.encodeAsPacket().encode()
        let packets = PacketParser().append(wire)
        guard packets.count == 1, packets[0].type == .control else { return nil }
        return ControlMessage.decode(from: packets[0].payload)
    }

    func testSetISORoundTrip() {
        let back = roundTrip(.setISO(800))
        XCTAssertEqual(back?.type, "setISO")
        XCTAssertEqual(back?.floatValue, 800)
    }

    func testSetFPSRoundTrip() {
        let back = roundTrip(.setFPS(30))
        XCTAssertEqual(back?.type, "setFPS")
        XCTAssertEqual(back?.intValue, 30)
    }

    func testSetLensRoundTrip() {
        let back = roundTrip(.setLens("0.5x"))
        XCTAssertEqual(back?.type, "setLens")
        XCTAssertEqual(back?.stringValue, "0.5x")
    }

    func testSetLUTCarriesNameAndEnabled() {
        let back = roundTrip(.setLUT(name: "Kodak2383", enabled: true))
        XCTAssertEqual(back?.type, "setLUT")
        XCTAssertEqual(back?.lutName, "Kodak2383")
        XCTAssertEqual(back?.boolValue, true)
    }

    func testStateSnapshotRoundTripIsLossless() {
        let snap = StateSnapshot(
            iso: 400, shutterDenom: 50, wbKelvin: 5600, tint: -3,
            lens: "1x", zoom: 1.0, focusAuto: false, focusPosition: 0.42,
            fps: 30, exposureAuto: true, whiteBalanceAuto: false,
            resolution: "4K", colorSpace: "Apple Log",
            lutName: nil, lutEnabled: false, isoCompensation: true,
            availableLenses: ["0.5x", "1x", "2x"], deviceModel: "iPhone 15 Pro Max")
        let back = roundTrip(.state(snap))
        XCTAssertEqual(back?.type, "state")
        // StateSnapshot is Equatable → full structural equality.
        XCTAssertEqual(back?.state, snap)
    }

    func testDecodeOfGarbageReturnsNil() {
        XCTAssertNil(ControlMessage.decode(from: Data([0x7B, 0x00, 0xFF])))  // "{" + junk
        XCTAssertNil(ControlMessage.decode(from: Data()))
    }

    // MARK: Hello (PROTOCOL-COMPAT-SPEC §2)

    func testHelloRoundTrip() {
        let h = HelloMessage(app: "camera", appVersion: "1.6.0",
                             proto: 2, minProto: 1, caps: ["auth", "tally"])
        let back = roundTrip(.hello(h))
        XCTAssertEqual(back?.type, "hello")
        XCTAssertEqual(back?.hello, h)
    }

    func testHelloToleratesMissingKeys() throws {
        // A sparse hello (only `app`) from a future/older peer decodes to
        // defaults, never throws — the tolerant-reader law.
        let h = try JSONDecoder().decode(HelloMessage.self, from: Data(#"{"app":"bridge"}"#.utf8))
        XCTAssertEqual(h.app, "bridge")
        XCTAssertEqual(h.proto, 1)
        XCTAssertEqual(h.minProto, 1)
        XCTAssertEqual(h.caps, [])
    }

    // MARK: Additive-only back-compat (the decodeIfPresent law)

    func testControlMessageIgnoresUnknownJSONKeys() throws {
        // Forward-compat: a message from a NEWER peer carrying a key this build
        // doesn't know must still decode (JSONDecoder ignores unknown keys).
        let json = Data(#"{"type":"setISO","floatValue":800,"futureKnob":42}"#.utf8)
        let msg = try JSONDecoder().decode(ControlMessage.self, from: json)
        XCTAssertEqual(msg.type, "setISO")
        XCTAssertEqual(msg.floatValue, 800)
    }

    func testOldStateSnapshotJSONWithoutNewKeysDecodes() throws {
        // An OLD sender: JSON with ONLY the original pre-additive fields (no
        // outputRotation/videoActive/capabilities/codec/…).  The custom
        // init(from:) must fill defaults, NOT throw keyNotFound — which would
        // drop the ENTIRE state packet (every field, not just the missing one).
        let json = Data("""
        {"iso":400,"shutterDenom":50,"wbKelvin":5600,"tint":0,"zoom":1,
         "focusAuto":true,"focusPosition":0.5,"fps":30,"exposureAuto":true,
         "whiteBalanceAuto":true,"resolution":"4K","colorSpace":"Apple Log",
         "lutEnabled":false,"isoCompensation":false,"availableLenses":["1x"],
         "deviceModel":"iPhone 15 Pro"}
        """.utf8)
        let snap = try JSONDecoder().decode(StateSnapshot.self, from: json)
        XCTAssertEqual(snap.iso, 400)
        XCTAssertEqual(snap.outputRotation, 0)                    // additive default
        XCTAssertEqual(snap.videoActive, true)                   // additive default
        XCTAssertEqual(snap.remoteControlAllowed, true)
        XCTAssertEqual(snap.codec, "")                           // additive default
        XCTAssertEqual(snap.exposureBias, 0)
        XCTAssertEqual(snap.stabilization, "")                   // additive default
        XCTAssertEqual(snap.capabilities, DeviceCapabilities())  // default struct
    }

    func testPartialCapabilitiesDecodesToDefaults() throws {
        // A capabilities object with only SOME keys (future/older sender) decodes
        // the present ones and defaults the rest, never throws.
        let caps = try JSONDecoder().decode(
            DeviceCapabilities.self, from: Data(#"{"isoMin":50,"supportedFps":[24,30]}"#.utf8))
        XCTAssertEqual(caps.isoMin, 50)
        XCTAssertEqual(caps.supportedFps, [24, 30])
        XCTAssertEqual(caps.isoMax, 3200)      // default
        XCTAssertEqual(caps.evBiasMin, -2)     // default
        XCTAssertEqual(caps.availableLuts, []) // additive default (remote LUT picker)
        XCTAssertEqual(caps.zoomMax, 0)        // additive default → receiver fallback
        XCTAssertEqual(caps.stabilizations, [])// additive default
        XCTAssertEqual(caps.colorSpaces, [])   // additive default
    }

    func testSetStabilizationRoundTrip() {
        let back = roundTrip(.setStabilization("High"))
        XCTAssertEqual(back?.type, "setStabilization")
        XCTAssertEqual(back?.stringValue, "High")
    }

    func testSetColorSpaceRoundTrip() {
        // Exact rawValue strings — "Rec.2020 HLG", not the old doc-comment's
        // "HLG BT.2020" (senders using the wrong spelling get ignored+resync).
        let back = roundTrip(.setColorSpace("Rec.2020 HLG"))
        XCTAssertEqual(back?.type, "setColorSpace")
        XCTAssertEqual(back?.stringValue, "Rec.2020 HLG")
    }

    func testFocusAndExposurePointRoundTrip() {
        let f = roundTrip(.setFocusPoint(x: 0.25, y: 0.75))
        XCTAssertEqual(f?.type, "setFocusPoint")
        XCTAssertEqual(f?.pointX, 0.25)
        XCTAssertEqual(f?.pointY, 0.75)
        let e = roundTrip(.setExposurePoint(x: 1, y: 0))
        XCTAssertEqual(e?.type, "setExposurePoint")
        XCTAssertEqual(e?.pointX, 1)
        XCTAssertEqual(e?.pointY, 0)
    }

    func testRemoteControlCapabilitiesRoundTripLossless() {
        // The new remote-control fields survive the full wire path intact.
        var caps = DeviceCapabilities()
        caps.availableLuts = ["Kodak2383", "FujiEterna"]
        caps.zoomMax = 15.5
        caps.stabilizations = ["Standard", "High"]
        let snap = StateSnapshot(
            iso: 400, shutterDenom: 50, wbKelvin: 5600, tint: 0,
            lens: "1x", zoom: 1, focusAuto: true, focusPosition: 0.5,
            fps: 30, exposureAuto: true, whiteBalanceAuto: true,
            resolution: "4K", colorSpace: "Apple Log",
            lutName: "Kodak2383", lutEnabled: true, isoCompensation: false,
            availableLenses: ["1x"], deviceModel: "iPhone 15 Pro",
            capabilities: caps, stabilization: "High")
        let back = roundTrip(.state(snap))
        XCTAssertEqual(back?.state?.capabilities.availableLuts, ["Kodak2383", "FujiEterna"])
        XCTAssertEqual(back?.state?.capabilities.zoomMax, 15.5)
        XCTAssertEqual(back?.state?.capabilities.stabilizations, ["Standard", "High"])
        XCTAssertEqual(back?.state?.stabilization, "High")
    }
}
