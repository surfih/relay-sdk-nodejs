import { createHmac, generateKeyPairSync, sign, verify, type KeyObject } from "node:crypto";
import assert from "node:assert/strict";
import { test } from "node:test";
import {
  SIGNATURE_FORMAT_ERROR,
  assertApiKey,
  assertIdempotencyKey,
  assertSignatureHeader,
  hmacSha256Header,
  loadEd25519PrivateKey,
  loadEd25519PublicKey,
  sha256Hex,
  signEd25519,
  signingBytes,
  verifyEd25519Signature,
  webhookHmacHeader,
} from "../src/sign.js";
import { DEFAULT_QUEUE_RULES, MAX_IDEMPOTENCY_KEY_LENGTH, type JsonValue } from "../src/index.js";
import * as sdk from "../src/index.js";

const SECRET = "cs_live_test";
const API_KEY = "ak_live_test";

test("HMAC request vector is locked", () => {
  const body = new TextEncoder().encode('{"name":"messages"}');
  const message = signingBytes(API_KEY, "1700000000", "post", "/api/v1/queues", body);
  assert.equal(
    new TextDecoder().decode(message),
    'ak_live_test.1700000000.POST./api/v1/queues.{"name":"messages"}',
  );
  assert.equal(
    hmacSha256Header(SECRET, message),
    "sha256=2c5994b3afe0f720c9abef5581abca5f5af340c9e230608b1fb8feb664d84012",
  );
  assert.equal(
    createHmac("sha256", SECRET)
      .update('ak_live_test.1700000000.POST./api/v1/queues.{"name":"messages"}')
      .digest("hex"),
    "2c5994b3afe0f720c9abef5581abca5f5af340c9e230608b1fb8feb664d84012",
  );
});

test("webhook HMAC vector uses five updates and respects Uint8Array views", () => {
  const raw = new TextEncoder().encode('{"event_id":"evt_1"}');
  const timestamp = "1700000000";
  assert.equal(
    webhookHmacHeader(SECRET, API_KEY, timestamp, raw),
    "sha256=d65676f920079ade2fc4491284af46cb0fb1192079cc6727f431e8ad69f71972",
  );

  const padded = new Uint8Array(raw.length + 2);
  padded[0] = 0xff;
  padded[padded.length - 1] = 0xff;
  padded.set(raw, 1);
  const view = padded.subarray(1, 1 + raw.length);
  assert.equal(
    webhookHmacHeader(SECRET, API_KEY, timestamp, view),
    webhookHmacHeader(SECRET, API_KEY, timestamp, raw),
  );
  assert.notEqual(
    webhookHmacHeader(SECRET, API_KEY, timestamp, padded),
    webhookHmacHeader(SECRET, API_KEY, timestamp, raw),
  );
  assert.equal(sha256Hex(view), sha256Hex(raw));
  assert.notEqual(sha256Hex(padded), sha256Hex(raw));
});

test("signing bytes copy a body view and GET ends with a dot", () => {
  const body = new TextEncoder().encode("{}");
  const padded = new Uint8Array(body.length + 4);
  padded.set(body, 2);
  const view = padded.subarray(2, 2 + body.length);
  const fromView = signingBytes(API_KEY, "1700000000", "POST", "/api/v1/queues", view);
  const fromBody = signingBytes(API_KEY, "1700000000", "POST", "/api/v1/queues", body);
  assert.deepEqual(fromView, fromBody);

  const get = signingBytes(API_KEY, "1700000000", "GET", "/api/v1/events/evt_1", new Uint8Array());
  assert.equal(new TextDecoder().decode(get), "ak_live_test.1700000000.GET./api/v1/events/evt_1.");
});

test("Ed25519 sign and verify round-trip a 64-byte signature", () => {
  const { privateKey, publicKey } = generateKeyPairSync("ed25519");
  const privatePem = exportPem(privateKey, "pkcs8");
  const publicPem = exportPem(publicKey, "spki");
  const message = signingBytes(API_KEY, "1700000000", "GET", "/api/v1/events/evt_1", new Uint8Array());
  const header = signEd25519(loadEd25519PrivateKey(privatePem), message);
  assert.match(header, /^ed25519=[A-Za-z0-9+/]{86}==$/);
  assert.equal(verifyEd25519Signature(loadEd25519PublicKey(publicPem), message, header), true);

  const raw = Buffer.from(header.slice("ed25519=".length), "base64");
  assert.equal(raw.length, 64);
  assert.equal(verify(null, message, publicKey, raw), true);
  raw[0] = raw[0] === 0 ? 1 : 0;
  const tampered = `ed25519=${raw.toString("base64")}`;
  assert.equal(verifyEd25519Signature(loadEd25519PublicKey(publicPem), message, tampered), false);
});

test("Ed25519 signing uses the Uint8Array view", () => {
  const { privateKey, publicKey } = generateKeyPairSync("ed25519");
  const pem = exportPem(privateKey, "pkcs8");
  const message = new TextEncoder().encode("view-message");
  const padded = new Uint8Array(message.length + 2);
  padded.set(message, 1);
  const view = padded.subarray(1, 1 + message.length);
  const header = signEd25519(loadEd25519PrivateKey(pem), view);
  const raw = Buffer.from(header.slice("ed25519=".length), "base64");
  assert.equal(verify(null, message, publicKey, raw), true);
  assert.equal(verify(null, padded, publicKey, raw), false);
});

test("rejects non-Ed25519 and non-PKCS8 private keys without echoing the PEM", () => {
  const { privateKey } = generateKeyPairSync("ec", { namedCurve: "P-256" });
  const pem = exportPem(privateKey, "pkcs8");
  assert.throws(
    () => loadEd25519PrivateKey(pem),
    (err: unknown) => {
      assert.equal(err instanceof TypeError, true);
      assert.equal((err as TypeError).message, "privateKeyPem must be a PKCS#8 Ed25519 private key");
      assert.equal((err as TypeError).message.includes("BEGIN"), false);
      assert.equal(String(err).includes(pem.slice(30, 60)), false);
      return true;
    },
  );
  assert.throws(
    () => loadEd25519PrivateKey("-----BEGIN PUBLIC KEY-----\nMCow\n-----END PUBLIC KEY-----\n"),
    /PKCS#8 Ed25519 private key/,
  );
});

test("custom signature header must be canonical sha256 or ed25519", () => {
  const hmac = `sha256=${"ab".repeat(32)}`;
  assert.equal(assertSignatureHeader(`  ${hmac}\n`), hmac);
  assert.throws(
    () => assertSignatureHeader(`sha256=${"AB".repeat(32)}`),
    (err: unknown) => err instanceof TypeError && (err as TypeError).message === SIGNATURE_FORMAT_ERROR,
  );
  assert.throws(
    () => assertSignatureHeader("ed25519=aaaa"),
    (err: unknown) => {
      assert.equal((err as TypeError).message, SIGNATURE_FORMAT_ERROR);
      assert.equal((err as TypeError).message.includes("aaaa"), false);
      return true;
    },
  );

  const { privateKey } = generateKeyPairSync("ed25519");
  const raw = sign(null, Buffer.from("m"), privateKey);
  const encoded = raw.toString("base64");
  assert.equal(assertSignatureHeader(`ed25519=${encoded}`), `ed25519=${encoded}`);
  assert.throws(() => assertSignatureHeader(`ed25519=-${encoded.slice(1)}`), TypeError);
  assert.throws(() => assertSignatureHeader(`ed25519=${encoded.slice(0, -2)}`), TypeError);
});

test("idempotency keys are trimmed, counted in code points, and limited to printable ASCII", () => {
  assert.equal(assertIdempotencyKey("  order-1  "), "order-1");
  assert.equal(assertIdempotencyKey("a".repeat(MAX_IDEMPOTENCY_KEY_LENGTH)).length, 200);
  assert.throws(() => assertIdempotencyKey("a".repeat(201)), /at most 200 characters/);
  assert.throws(() => assertIdempotencyKey("   "), /must not be empty/);
  assert.throws(() => assertIdempotencyKey("ab\ncd"), /printable ASCII/);
  assert.throws(() => assertIdempotencyKey("ab\rcd"), /printable ASCII/);
  assert.throws(() => assertIdempotencyKey("ab\0cd"), /printable ASCII/);
  assert.throws(() => assertIdempotencyKey("é".repeat(150)), /printable ASCII/);
  assert.throws(() => assertIdempotencyKey("é".repeat(201)), /at most 200 characters/);
  assert.throws(() => assertIdempotencyKey(undefined as unknown as string), /must be a string/);
});

test("api keys must be non-empty printable ASCII", () => {
  assert.equal(assertApiKey("ak_live_test"), "ak_live_test");
  assert.throws(() => assertApiKey(""), /non-empty string/);
  assert.throws(() => assertApiKey("ak_live_\n"), /printable ASCII/);
  assert.throws(() => assertApiKey("ak\0live"), /printable ASCII/);
});

test("public entry does not export paths or header names", () => {
  assert.equal("paths" in sdk, false);
  assert.equal("API_KEY_HEADER" in sdk, false);
  assert.equal("PAYLOAD_SIGNATURE_HEADER" in sdk, false);
  assert.equal("IDEMPOTENCY_KEY_HEADER" in sdk, false);
  assert.equal(sdk.MAX_IDEMPOTENCY_KEY_LENGTH, 200);
  assert.equal(sdk.TIMESTAMP_SKEW_SECONDS, 300);
  assert.equal(DEFAULT_QUEUE_RULES.max_attempts, 8);
  const sample: JsonValue = { ok: true };
  assert.equal(typeof sample, "object");
});

function exportPem(key: KeyObject, type: "pkcs8" | "spki"): string {
  const exported =
    type === "pkcs8" ? key.export({ type: "pkcs8", format: "pem" }) : key.export({ type: "spki", format: "pem" });
  if (typeof exported !== "string") throw new Error("expected PEM text");
  return exported;
}
