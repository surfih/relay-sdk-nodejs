import { createHash, createHmac, generateKeyPairSync, sign } from "node:crypto";
import assert from "node:assert/strict";
import { test } from "node:test";
import { WebhookVerificationError, verifyWebhook } from "../src/index.js";

const API_KEY = "ak_live_test";
const SECRET = "cs_live_webhook_secret_value";
const TIMESTAMP = "1700000000";
const NOW_MS = 1_700_000_000_000;

function delivery(over: Record<string, unknown> = {}): string {
  return JSON.stringify({
    event_id: "evt_1",
    queue_id: "que_1",
    event_type: "order.created",
    event: { id: "ord_1" },
    attempt: 1,
    created_at: "2026-10-28T12:00:00Z",
    ...over,
  });
}

function hmac(raw: Uint8Array, timestamp = TIMESTAMP, apiKey = API_KEY): string {
  return `sha256=${createHmac("sha256", SECRET)
    .update(apiKey)
    .update(".")
    .update(timestamp)
    .update(".")
    .update(raw)
    .digest("hex")}`;
}

function headersFor(
  raw: Uint8Array,
  extra: Record<string, string | string[]> = {},
  apiKey = API_KEY,
  timestamp = TIMESTAMP,
): Record<string, string | string[]> {
  return {
    "X-API-Key": ` ${apiKey} `,
    "X-Timestamp": ` ${timestamp} `,
    "X-Payload-Signature": hmac(raw, timestamp, apiKey),
    "Idempotency-Key": " order-1 ",
    "X-Event-Id": " evt_1 ",
    "X-Event-Attempt": " 1 ",
    "X-Queue-Id": " que_1 ",
    ...extra,
  };
}

function pemText(value: unknown): string {
  if (typeof value !== "string") throw new Error("expected PEM text");
  return value;
}

function assertNoSecrets(err: unknown, secrets: readonly string[]): void {
  const error = err as Error;
  const blob = [error.message, error.stack ?? "", JSON.stringify(error, Object.getOwnPropertyNames(error))].join("\n");
  for (const secret of secrets) assert.equal(blob.includes(secret), false);
}

function verifyOpts(
  raw: string | Uint8Array,
  headers: Record<string, string | string[]>,
  over: Record<string, unknown> = {},
) {
  return {
    apiKey: API_KEY,
    secret: SECRET,
    rawBody: raw,
    headers,
    now: () => NOW_MS,
    ...over,
  };
}

test("verifies a good delivery and trims headers", () => {
  const raw = delivery();
  const bytes = new TextEncoder().encode(raw);
  const verified = verifyWebhook(verifyOpts(raw, headersFor(bytes)));
  assert.equal(verified.eventId, "evt_1");
  assert.equal(verified.queueId, "que_1");
  assert.equal(verified.attempt, 1);
  assert.equal(verified.idempotencyKey, "order-1");
  assert.equal(verified.body.event_type, "order.created");
});

test("a swapped Idempotency-Key still verifies", () => {
  const raw = delivery();
  const bytes = new TextEncoder().encode(raw);
  const verified = verifyWebhook(
    verifyOpts(bytes, headersFor(bytes, { "Idempotency-Key": "swapped-key" })),
  );
  assert.equal(verified.idempotencyKey, "swapped-key");
  assert.equal(verified.eventId, "evt_1");
  assert.equal(verified.attempt, 1);
});

test("bad signatures fail closed and do not reveal the secret or expected MAC", () => {
  const raw = delivery();
  const bytes = new TextEncoder().encode(raw);
  const expected = hmac(bytes);
  const headers = headersFor(bytes, { "X-Payload-Signature": "sha256=" + "ab".repeat(32) });
  assert.throws(
    () => verifyWebhook(verifyOpts(bytes, headers)),
    (err: unknown) => {
      assert.equal(err instanceof WebhookVerificationError, true);
      assert.equal((err as WebhookVerificationError).reason, "signature");
      assert.equal((err as WebhookVerificationError).message, "webhook signature verification failed");
      assertNoSecrets(err, [SECRET, expected]);
      return true;
    },
  );

  assert.throws(
    () => verifyWebhook(verifyOpts(bytes, headersFor(bytes, {}, "ak_live_other"))),
    (err: unknown) => (err as WebhookVerificationError).reason === "signature",
  );
  assert.throws(
    () =>
      verifyWebhook(
        verifyOpts(bytes, headersFor(bytes, { "X-API-Key": "short" })),
      ),
    (err: unknown) => err instanceof WebhookVerificationError && (err as WebhookVerificationError).reason === "signature",
  );
});

test("multi-value headers fail and a single-element array is accepted", () => {
  const raw = delivery();
  const bytes = new TextEncoder().encode(raw);
  assert.throws(
    () =>
      verifyWebhook(
        verifyOpts(bytes, headersFor(bytes, { "Idempotency-Key": ["order-1", "other"] })),
      ),
    (err: unknown) => (err as WebhookVerificationError).reason === "headers",
  );
  assert.throws(
    () =>
      verifyWebhook(
        verifyOpts(bytes, headersFor(bytes, { "X-API-Key": [API_KEY, "ak_live_other"] })),
      ),
    (err: unknown) => (err as WebhookVerificationError).reason === "headers",
  );

  const verified = verifyWebhook(
    verifyOpts(bytes, headersFor(bytes, { "Idempotency-Key": [" order-1 "] })),
  );
  assert.equal(verified.idempotencyKey, "order-1");
});

test("invalid JSON after a good MAC is a body error and a bad MAC wins first", () => {
  const marker = "NOT_JSON_SECRET_MARKER";
  const bytes = new TextEncoder().encode(marker);
  assert.throws(
    () => verifyWebhook(verifyOpts(bytes, headersFor(bytes))),
    (err: unknown) => {
      assert.equal((err as WebhookVerificationError).reason, "body");
      assert.equal((err as WebhookVerificationError).message, "webhook body is invalid");
      assertNoSecrets(err, [marker, SECRET]);
      return true;
    },
  );
  assert.throws(
    () =>
      verifyWebhook(
        verifyOpts(bytes, headersFor(bytes, { "X-Payload-Signature": "sha256=" + "cd".repeat(32) })),
      ),
    (err: unknown) => (err as WebhookVerificationError).reason === "signature",
  );
});

test("identity mismatches use reason mismatch", () => {
  const raw = delivery();
  const bytes = new TextEncoder().encode(raw);
  assert.throws(
    () =>
      verifyWebhook(
        verifyOpts(bytes, headersFor(bytes, { "X-Event-Id": "evt_other" })),
      ),
    (err: unknown) => {
      assert.equal((err as WebhookVerificationError).reason, "mismatch");
      assert.equal((err as WebhookVerificationError).message, "webhook payload does not match signed headers");
      assert.equal((err as WebhookVerificationError).message.includes("evt_other"), false);
      return true;
    },
  );
  assert.throws(
    () =>
      verifyWebhook(
        verifyOpts(bytes, headersFor(bytes, { "X-Event-Attempt": "2" })),
      ),
    (err: unknown) => (err as WebhookVerificationError).reason === "mismatch",
  );
  assert.throws(
    () =>
      verifyWebhook(
        verifyOpts(bytes, headersFor(bytes, { "X-Queue-Id": "que_other" })),
      ),
    (err: unknown) => (err as WebhookVerificationError).reason === "mismatch",
  );

  const fractional = new TextEncoder().encode(delivery({ attempt: 1.5 }));
  assert.throws(
    () => verifyWebhook(verifyOpts(fractional, headersFor(fractional))),
    (err: unknown) => (err as WebhookVerificationError).reason === "body",
  );
});

test("HMAC verification requires a fresh X-Timestamp and ignores a stale X-Event-Timestamp", () => {
  const raw = delivery();
  const bytes = new TextEncoder().encode(raw);

  const verified = verifyWebhook(
    verifyOpts(bytes, headersFor(bytes, { "X-Event-Timestamp": "1" })),
  );
  assert.equal(verified.attempt, 1);

  assert.throws(
    () =>
      verifyWebhook(
        verifyOpts(bytes, headersFor(bytes, {}, API_KEY, "1"), {
          now: () => Date.now(),
        }),
      ),
    (err: unknown) => (err as WebhookVerificationError).reason === "timestamp",
  );

  assert.throws(
    () =>
      verifyWebhook(
        verifyOpts(bytes, headersFor(bytes), {
          now: () => (1_700_000_000 + 301) * 1000,
        }),
      ),
    (err: unknown) => (err as WebhookVerificationError).reason === "timestamp",
  );

  const edge = verifyWebhook(
    verifyOpts(bytes, headersFor(bytes), {
      now: () => (1_700_000_000 + 300) * 1000,
    }),
  );
  assert.equal(edge.attempt, 1);

  assert.throws(
    () =>
      verifyWebhook(
        verifyOpts(bytes, headersFor(bytes, { "X-Timestamp": "12ab" }, API_KEY, "12ab")),
      ),
    (err: unknown) => (err as WebhookVerificationError).reason === "timestamp",
  );

  const { "X-Timestamp": _ignored, ...missingTs } = headersFor(bytes);
  void _ignored;
  assert.throws(
    () => verifyWebhook(verifyOpts(bytes, missingTs)),
    (err: unknown) => (err as WebhookVerificationError).reason === "headers",
  );
});

test("Ed25519 delivery signature enforces the v1 message and ±300s skew", () => {
  const { privateKey, publicKey } = generateKeyPairSync("ed25519");
  const publicPem = pemText(publicKey.export({ type: "spki", format: "pem" }));
  const raw = new TextEncoder().encode(delivery());
  const timestamp = TIMESTAMP;

  const verified = verifyWebhook({
    ...verifyOpts(raw, deliveryHeaders(raw, privateKey, timestamp)),
    deliveryPublicKeyPem: publicPem,
  });
  assert.equal(verified.eventId, "evt_1");

  assert.throws(
    () =>
      verifyWebhook({
        ...verifyOpts(raw, deliveryHeaders(raw, privateKey, timestamp), {
          now: () => (1_700_000_000 + 301) * 1000,
        }),
        deliveryPublicKeyPem: publicPem,
      }),
    (err: unknown) => (err as WebhookVerificationError).reason === "timestamp",
  );
  assert.throws(
    () =>
      verifyWebhook({
        ...verifyOpts(raw, deliveryHeaders(raw, privateKey, timestamp), {
          now: () => (1_700_000_000 - 301) * 1000,
        }),
        deliveryPublicKeyPem: publicPem,
      }),
    (err: unknown) => (err as WebhookVerificationError).reason === "timestamp",
  );

  const edge = verifyWebhook({
    ...verifyOpts(raw, deliveryHeaders(raw, privateKey, timestamp), {
      now: () => (1_700_000_000 + 300) * 1000,
    }),
    deliveryPublicKeyPem: publicPem,
  });
  assert.equal(edge.attempt, 1);

  const paddedTime = "01700000000";
  const padded = verifyWebhook({
    ...verifyOpts(raw, deliveryHeaders(raw, privateKey, paddedTime, TIMESTAMP)),
    deliveryPublicKeyPem: publicPem,
  });
  assert.equal(padded.eventId, "evt_1");

  assert.throws(
    () =>
      verifyWebhook({
        ...verifyOpts(raw, deliveryHeaders(raw, privateKey, "12ab")),
        deliveryPublicKeyPem: publicPem,
      }),
    (err: unknown) => (err as WebhookVerificationError).reason === "timestamp",
  );

  const badSig = deliveryHeaders(raw, privateKey, timestamp);
  badSig["X-Event-Signature"] = "ed25519=" + "A".repeat(86) + "==";
  assert.throws(
    () =>
      verifyWebhook({
        ...verifyOpts(raw, badSig),
        deliveryPublicKeyPem: publicPem,
      }),
    (err: unknown) => (err as WebhookVerificationError).reason === "delivery",
  );

  const { "X-Event-Key-Id": _ignored, ...missingKey } = deliveryHeaders(raw, privateKey, timestamp);
  void _ignored;
  assert.throws(
    () =>
      verifyWebhook({
        ...verifyOpts(raw, missingKey),
        deliveryPublicKeyPem: publicPem,
      }),
    (err: unknown) => (err as WebhookVerificationError).reason === "headers",
  );
});

test("a private key PEM is not a delivery public key and is not echoed", () => {
  const raw = new TextEncoder().encode(delivery());
  const { privateKey } = generateKeyPairSync("ed25519");
  const privatePem = pemText(privateKey.export({ type: "pkcs8", format: "pem" }));
  const marker = privatePem.slice(40, 80);
  assert.throws(
    () =>
      verifyWebhook({
        ...verifyOpts(
          raw,
          headersFor(raw, {
            "X-Event-Timestamp": TIMESTAMP,
            "X-Event-Key-Id": "whk_1",
            "X-Event-Signature": "ed25519=" + "A".repeat(86) + "==",
          }),
        ),
        deliveryPublicKeyPem: privatePem,
      }),
    (err: unknown) => {
      assert.equal((err as WebhookVerificationError).reason, "delivery");
      assert.equal((err as WebhookVerificationError).message, "webhook delivery signature verification failed");
      assertNoSecrets(err, [marker, SECRET, privatePem]);
      return true;
    },
  );
});

test("hashes a Uint8Array view of the raw body", () => {
  const raw = new TextEncoder().encode(delivery());
  const padded = new Uint8Array(raw.length + 2);
  padded[0] = 0x11;
  padded[padded.length - 1] = 0x22;
  padded.set(raw, 1);
  const view = padded.subarray(1, 1 + raw.length);
  const verified = verifyWebhook(verifyOpts(view, headersFor(view)));
  assert.equal(verified.body.event_id, "evt_1");
});

function deliveryHeaders(
  raw: Uint8Array,
  privateKey: ReturnType<typeof generateKeyPairSync>["privateKey"],
  eventTimestamp: string,
  hmacTimestamp = TIMESTAMP,
) {
  return headersFor(
    raw,
    {
      "X-Event-Timestamp": eventTimestamp,
      "X-Event-Key-Id": " whk_1 ",
      "X-Event-Signature": signDelivery(privateKey, eventTimestamp, "evt_1", raw),
    },
    API_KEY,
    hmacTimestamp,
  );
}

function signDelivery(
  privateKey: ReturnType<typeof generateKeyPairSync>["privateKey"],
  timestamp: string,
  eventId: string,
  raw: Uint8Array,
): string {
  const digest = createHash("sha256").update(raw).digest("hex");
  const message = Buffer.from(`v1.${timestamp}.${eventId}.${digest}`);
  return `ed25519=${sign(null, message, privateKey).toString("base64")}`;
}
