"""
HeyJournal — Cryptographic Correctness & NIST SP 800-38D Test Suite
Verifies `public/crypto.js` pure-JS SHA-256, PBKDF2-HMAC-SHA256, and AES-256-GCM
against official NIST test vectors, Python hashlib, and tamper rejection invariants.
"""
import hashlib
import json
import os
import shutil
import subprocess
import unittest

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def find_js_runner():
    node = shutil.which("node")
    if node:
        return "node", node
    for cand in (
        "/System/Library/Frameworks/JavaScriptCore.framework/Versions/Current/Helpers/jsc",
        shutil.which("jsc"),
    ):
        if cand and os.path.isfile(cand) and os.access(cand, os.X_OK):
            return "jsc", cand
    return None, None


def run_es_module_snippet(js_code):
    engine, binary = find_js_runner()
    if not engine:
        raise unittest.SkipTest("No JS engine (node or jsc) installed to execute crypto.js")

    if engine == "node":
        cmd = [binary, "--input-type=module", "-e", js_code]
    else:
        cmd = [binary, "-m", "-e", js_code]

    res = subprocess.run(cmd, cwd=BASE_DIR, capture_output=True, text=True)
    if res.returncode != 0:
        raise AssertionError(f"{engine} execution failed:\nSTDOUT:\n{res.stdout}\nSTDERR:\n{res.stderr}")
    return res.stdout.strip()


class TestZeroKnowledgeCryptoEngine(unittest.TestCase):
    def test_sha256_and_pbkdf2_match_openssl_hashlib(self):
        js = """
        import { _pureJs } from "./public/crypto.js";
        const toBytes = (s) => new Uint8Array(Array.from(s).map((c) => c.charCodeAt(0)));
        const toHex = (a) => Array.from(a).map((b) => b.toString(16).padStart(2, "0")).join("");

        const hEmpty = toHex(_pureJs.sha256(new Uint8Array(0)));
        const hAbc = toHex(_pureJs.sha256(toBytes("abc")));
        const hLong = toHex(_pureJs.sha256(toBytes("a".repeat(128))));
        const pb = toHex(_pureJs.pbkdf2Sha256Pure(toBytes("hunter2-strong-passphrase"), toBytes("0123456789abcdef"), 10000, 64));

        const out = JSON.stringify({ hEmpty, hAbc, hLong, pb });
        if (typeof print === "function") print(out); else console.log(out);
        """
        out = json.loads(run_es_module_snippet(js))
        self.assertEqual(out["hEmpty"], hashlib.sha256(b"").hexdigest())
        self.assertEqual(out["hAbc"], hashlib.sha256(b"abc").hexdigest())
        self.assertEqual(out["hLong"], hashlib.sha256(b"a" * 128).hexdigest())
        expected_pb = hashlib.pbkdf2_hmac("sha256", b"hunter2-strong-passphrase", b"0123456789abcdef", 10000, 64).hex()
        self.assertEqual(out["pb"], expected_pb)

    def test_nist_sp_800_38d_aes_256_gcm_vectors_and_tamper_rejection(self):
        js = """
        import { _pureJs } from "./public/crypto.js";
        const fromHex = (h) => new Uint8Array(h.length ? h.match(/.{2}/g).map((b) => parseInt(b, 16)) : []);
        const toHex = (a) => Array.from(a).map((b) => b.toString(16).padStart(2, "0")).join("");

        // NIST Test Case 13 (zero key/iv, empty plaintext/AAD)
        const tc13 = toHex(_pureJs.aes256GcmEncryptPure(fromHex("00".repeat(32)), fromHex("00".repeat(12)), new Uint8Array(0), new Uint8Array(0)));

        // NIST Test Case 14 (zero key/iv, 16 zero-byte plaintext)
        const tc14Raw = _pureJs.aes256GcmEncryptPure(fromHex("00".repeat(32)), fromHex("00".repeat(12)), fromHex("00".repeat(16)), new Uint8Array(0));
        const tc14Ct = toHex(tc14Raw.subarray(0, 16));
        const tc14Tag = toHex(tc14Raw.subarray(16));

        // NIST Test Case 16 (plaintext + AAD)
        const k16 = fromHex("feffe9928665731c6d6a8f9467308308feffe9928665731c6d6a8f9467308308");
        const iv16 = fromHex("cafebabefacedbaddecaf888");
        const pt16 = fromHex("d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39");
        const aad16 = fromHex("feedfacedeadbeeffeedfacedeadbeefabaddad2");
        const ct16Raw = _pureJs.aes256GcmEncryptPure(k16, iv16, pt16, aad16);
        const ct16 = toHex(ct16Raw.subarray(0, pt16.length));
        const tag16 = toHex(ct16Raw.subarray(pt16.length));
        const dec16 = toHex(_pureJs.aes256GcmDecryptPure(k16, iv16, ct16Raw, aad16));

        // Tamper tests: flipping 1 bit in CT, tag, or AAD MUST throw
        let ctTamperRejected = false;
        const badCt = new Uint8Array(ct16Raw);
        badCt[0] ^= 0x01;
        try { _pureJs.aes256GcmDecryptPure(k16, iv16, badCt, aad16); } catch (e) { ctTamperRejected = true; }

        let tagTamperRejected = false;
        const badTag = new Uint8Array(ct16Raw);
        badTag[badTag.length - 1] ^= 0x80;
        try { _pureJs.aes256GcmDecryptPure(k16, iv16, badTag, aad16); } catch (e) { tagTamperRejected = true; }

        let aadTamperRejected = false;
        const badAad = new Uint8Array(aad16);
        badAad[0] ^= 0x01;
        try { _pureJs.aes256GcmDecryptPure(k16, iv16, ct16Raw, badAad); } catch (e) { aadTamperRejected = true; }

        const out = JSON.stringify({
          tc13, tc14Ct, tc14Tag, ct16, tag16,
          dec16Ok: dec16 === toHex(pt16),
          ctTamperRejected, tagTamperRejected, aadTamperRejected
        });
        if (typeof print === "function") print(out); else console.log(out);
        """
        out = json.loads(run_es_module_snippet(js))
        self.assertEqual(out["tc13"], "530f8afbc74536b9a963b4f1c4cb738b")
        self.assertEqual(out["tc14Ct"], "cea7403d4d606b6e074ec5d3baf39d18")
        self.assertEqual(out["tc14Tag"], "d0d1c8a799996bf0265b98b5d48ab919")
        self.assertEqual(
            out["ct16"],
            "522dc1f099567d07f47f37a32a84427d643a8cdcbfe5c0c97598a2bd2555d1aa8cb08e48590dbb3da7b08b1056828838c5f61e6393ba7a0abcc9f662",
        )
        self.assertEqual(out["tag16"], "76fc6ece0f4e1768cddf8853bb2d551b")
        self.assertTrue(out["dec16Ok"])
        self.assertTrue(out["ctTamperRejected"])
        self.assertTrue(out["tagTamperRejected"])
        self.assertTrue(out["aadTamperRejected"])

    def test_envelope_validation_and_invalid_iterations_rejected(self):
        js = """
        import { decryptJson, _pureJs, bytesToBase64 } from "./public/crypto.js";
        const key = new Uint8Array(32);

        let badIvRejected = false;
        try {
          const blob = JSON.stringify({ v: 1, alg: "A256GCM", iv: bytesToBase64(new Uint8Array(8)), ct: bytesToBase64(new Uint8Array(24)) });
          await decryptJson(blob, key);
        } catch (e) { badIvRejected = true; }

        let shortCtRejected = false;
        try {
          const blob = JSON.stringify({ v: 1, alg: "A256GCM", iv: bytesToBase64(new Uint8Array(12)), ct: bytesToBase64(new Uint8Array(8)) });
          await decryptJson(blob, key);
        } catch (e) { shortCtRejected = true; }

        let badIterRejected = false;
        try {
          _pureJs.pbkdf2Sha256Pure(new Uint8Array(4), new Uint8Array(16), 0, 64);
        } catch (e) { badIterRejected = true; }

        const out = JSON.stringify({ badIvRejected, shortCtRejected, badIterRejected });
        if (typeof print === "function") print(out); else console.log(out);
        """
        out = json.loads(run_es_module_snippet(js))
        self.assertTrue(out["badIvRejected"])
        self.assertTrue(out["shortCtRejected"])
        self.assertTrue(out["badIterRejected"])

    def test_recovery_key_format_normalization_and_aad_separation(self):
        js = """
        if (typeof globalThis.crypto === "undefined") {
          let seed = 42;
          globalThis.crypto = {
            getRandomValues(arr) {
              for (let i = 0; i < arr.length; i++) {
                seed = (seed * 1664525 + 1013904223) >>> 0;
                arr[i] = (seed >>> 24) & 0xff;
              }
              return arr;
            },
          };
        }
        import {
          DEFAULT_KDF_ITERATIONS,
          generateRecoveryKey,
          normalizeRecoveryKey,
          wrapDek,
          unwrapDek,
        } from "./public/crypto.js";

        const keyStr = generateRecoveryKey();
        const norm = normalizeRecoveryKey("  " + keyStr.toLowerCase() + "  ");
        // Crockford normalization maps O->0 and I/L->1, while rejecting U and wrong lengths
        const typoNorm = normalizeRecoveryKey("OOOO-IIII-LLLL-2222-3333-4444-5555-6666");
        const badNorm = normalizeRecoveryKey("UUUU-2222-3333-4444-5555-6666-7777-8888");

        // Verify recovery DEK wrap uses domain-separated AAD and cannot unwrap under password AAD
        const dek = new Uint8Array(32).fill(7);
        const recKek = new Uint8Array(32).fill(9);
        const wrapped = await wrapDek(dek, recKek, "heyjournal:recovery-dek:v1");
        const unwrapped = await unwrapDek(wrapped, recKek, "heyjournal:recovery-dek:v1");
        let crossAadRejected = false;
        try {
          await unwrapDek(wrapped, recKek, "heyjournal:dek:v1");
        } catch (e) {
          crossAadRejected = true;
        }

        const out = JSON.stringify({
          defaultIters: DEFAULT_KDF_ITERATIONS,
          keyStr,
          normLen: norm.length,
          typoNorm,
          badNorm,
          roundTripOk: unwrapped.length === 32 && unwrapped[0] === 7 && unwrapped[31] === 7,
          crossAadRejected,
        });
        if (typeof print === "function") print(out); else console.log(out);
        """
        out = json.loads(run_es_module_snippet(js))
        self.assertEqual(out["defaultIters"], 600000)
        self.assertRegex(out["keyStr"], r"^[0-9A-Z]{4}(-[0-9A-Z]{4}){7}$")
        self.assertEqual(out["normLen"], 32)
        self.assertEqual(out["typoNorm"], "00001111111122223333444455556666")
        self.assertEqual(out["badNorm"], "")
        self.assertTrue(out["roundTripOk"])
        self.assertTrue(out["crossAadRejected"])

    def test_async_pure_js_pbkdf2_matches_sync_pure_js(self):
        js = """
        import { _pureJs } from "./public/crypto.js";
        const toBytes = (s) => new Uint8Array(Array.from(s).map((c) => c.charCodeAt(0)));
        const toHex = (a) => Array.from(a).map((b) => b.toString(16).padStart(2, "0")).join("");
        const pw = toBytes("lan-http-passphrase");
        const salt = toBytes("0123456789abcdef");
        const syncHex = toHex(_pureJs.pbkdf2Sha256Pure(pw, salt, 26000, 64));
        const asyncHex = toHex(await _pureJs.pbkdf2Sha256PureAsync(pw, salt, 26000, 64));
        const out = JSON.stringify({ syncHex, asyncHex });
        if (typeof print === "function") print(out); else console.log(out);
        """
        out = json.loads(run_es_module_snippet(js))
        self.assertEqual(out["syncHex"], out["asyncHex"])


if __name__ == "__main__":
    unittest.main()
