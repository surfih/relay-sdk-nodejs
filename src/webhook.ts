import type { KeyObject } from "node:crypto";
import { TIMESTAMP_SKEW_SECONDS, type JsonValue, type WebhookDeliveryBody } from "relay-types";
import { WebhookVerificationError, isRecord } from "./errors.js";
import { readWebhookHeader, type WebhookHeaders } from "./read-header.js";
import {
  assertApiKey,
  assertSecret,
  loadEd25519PublicKey,
  rawBodyBytes,
  sha256Hex,
  timingSafeEqualText,
  verifyEd25519Signature,
  webhookHmacHeader,
} from "./sign.js";

/**
 * Options for {@link verifyWebhook}.
 *
 * `Idempotency-Key` is not covered by the HMAC or by the Ed25519 delivery signature.
 * Treat it as attacker-controlled. Dedupe on the signed pair `(event_id, attempt)` as well
 * as on the idempotency key. A swapped `Idempotency-Key` still verifies.
 *
 * `now` returns milliseconds since the Unix epoch (`Date.now`). It is used only when
 * `deliveryPublicKeyPem` is set. HMAC-only deliveries have no timestamp check.
 */
export interface VerifyWebhookOptions {
  apiKey: string;
  secret: string;
  /** Exact request bytes. A string is UTF-8 encoded. A `Uint8Array` view is hashed as that view. */
  rawBody: string | Uint8Array;
  headers: WebhookHeaders;
  /** SPKI Ed25519 public key. When set, `X-Event-Signature` is required and skew is ±300s. */
  deliveryPublicKeyPem?: string;
  /** Milliseconds since the Unix epoch. Defaults to `Date.now`. */
  now?: () => number;
}

export interface VerifiedWebhook<T extends JsonValue = JsonValue> {
  body: WebhookDeliveryBody<T>;
  idempotencyKey: string;
  eventId: string;
  queueId: string;
  attempt: number;
}

/**
 * Verify a relay → webhook delivery.
 *
 * Order: required headers, constant-time API key compare, HMAC over `apiKey + "." + rawBody`
 * (three updates), optional Ed25519 delivery signature and ±300s skew, then JSON parse,
 * then `event_id` / `queue_id` / `attempt` against the signed headers.
 *
 * `Idempotency-Key` is unsigned. Dedupe on `(event_id, attempt)` too. If a header value is a
 * `string[]` whose length is not 1, verification fails.
 */
export function verifyWebhook<T extends JsonValue = JsonValue>(
  options: VerifyWebhookOptions,
): VerifiedWebhook<T> {
  const apiKey = assertApiKey(options.apiKey);
  const secret = assertSecret(options.secret);
  const rawBody = rawBodyBytes(options.rawBody);
  const headers = options.headers;

  const headerApiKey = readWebhookHeader(headers, "x-api-key");
  const payloadSignature = readWebhookHeader(headers, "x-payload-signature");
  const idempotencyKey = readWebhookHeader(headers, "idempotency-key");
  const eventId = readWebhookHeader(headers, "x-event-id");
  const attemptHeader = readWebhookHeader(headers, "x-event-attempt");
  const queueId = readWebhookHeader(headers, "x-queue-id");

  if (!timingSafeEqualText(apiKey, headerApiKey)) {
    throw new WebhookVerificationError("signature");
  }

  const expected = webhookHmacHeader(secret, apiKey, rawBody);
  if (!timingSafeEqualText(expected, payloadSignature)) {
    throw new WebhookVerificationError("signature");
  }

  if (options.deliveryPublicKeyPem !== undefined) {
    verifyDelivery(options.deliveryPublicKeyPem, headers, rawBody, eventId, options.now ?? Date.now);
  }

  let parsed: unknown;
  try {
    parsed = JSON.parse(new TextDecoder().decode(rawBody)) as unknown;
  } catch {
    throw new WebhookVerificationError("body");
  }
  if (!isDeliveryBody(parsed)) throw new WebhookVerificationError("body");
  if (parsed.event_id !== eventId || parsed.queue_id !== queueId || attemptHeader !== String(parsed.attempt)) {
    throw new WebhookVerificationError("mismatch");
  }

  return {
    body: parsed as WebhookDeliveryBody<T>,
    idempotencyKey,
    eventId,
    queueId,
    attempt: parsed.attempt,
  };
}

function verifyDelivery(
  pem: string,
  headers: WebhookHeaders,
  rawBody: Uint8Array,
  eventId: string,
  now: () => number,
): void {
  const timestamp = readWebhookHeader(headers, "x-event-timestamp");
  readWebhookHeader(headers, "x-event-key-id");
  const signature = readWebhookHeader(headers, "x-event-signature");

  if (!/^[0-9]+$/.test(timestamp) || timestamp.length > 16) {
    throw new WebhookVerificationError("timestamp");
  }
  const ts = Number(timestamp);
  if (!Number.isSafeInteger(ts)) throw new WebhookVerificationError("timestamp");

  let key: KeyObject;
  try {
    key = loadEd25519PublicKey(pem);
  } catch {
    throw new WebhookVerificationError("delivery");
  }

  const message = new TextEncoder().encode(`v1.${timestamp}.${eventId}.${sha256Hex(rawBody)}`);
  if (!verifyEd25519Signature(key, message, signature)) {
    throw new WebhookVerificationError("delivery");
  }

  let nowMs: number;
  try {
    nowMs = now();
  } catch {
    throw new WebhookVerificationError("timestamp");
  }
  if (typeof nowMs !== "number" || !Number.isFinite(nowMs)) {
    throw new WebhookVerificationError("timestamp");
  }
  const nowSeconds = Math.floor(nowMs / 1000);
  if (!Number.isSafeInteger(nowSeconds) || Math.abs(nowSeconds - ts) > TIMESTAMP_SKEW_SECONDS) {
    throw new WebhookVerificationError("timestamp");
  }
}

function isDeliveryBody(value: unknown): value is {
  event_id: string;
  queue_id: string;
  event_type: string;
  event: JsonValue;
  attempt: number;
  created_at: string;
} {
  if (!isRecord(value)) return false;
  if (typeof value.event_id !== "string" || typeof value.queue_id !== "string") return false;
  if (typeof value.event_type !== "string" || typeof value.created_at !== "string") return false;
  if (!Object.prototype.hasOwnProperty.call(value, "event")) return false;
  return typeof value.attempt === "number" && Number.isSafeInteger(value.attempt);
}
