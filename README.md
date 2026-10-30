# relay-sdk

Signed client for Relay `/api/v1`, and a verifier for webhook deliveries. ESM, Node 20+. The only runtime dependency is `relay-types`.

## Install

Build `relay-types` first so this package can resolve its types:

```sh
cd ../relay-types && npm install && npm run build
cd ../relay-sdk-nodejs && npm install && npm run build
```

## HMAC

```ts
import { createRelay } from "relay-sdk";

const relay = createRelay({
  apiKey: process.env.RELAY_API_KEY!,
  secret: process.env.RELAY_API_SECRET!,
});

const created = await relay.queues.create(
  { name: "orders", webhook_url: "https://app.example.com/hooks/relay" },
  { idempotencyKey: "queue-orders" },
);

const accepted = await relay.events.submit(
  created.queue.id,
  { event_type: "order.created", event: { id: "ord_1" } },
  { idempotencyKey: "order-ord_1" },
);
```

The client signs `apiKey.timestamp.METHOD.pathAndQuery.rawBody` over the same UTF-8 bytes it sends. `GET` and `DELETE` sign an empty body (the string ends with `.`) and omit `Content-Type`.

## API

| Method | HTTP | Idempotency-Key |
| --- | --- | --- |
| `relay.queues.create(body, { idempotencyKey })` | `POST /api/v1/queues` | required |
| `relay.events.submit(queueId, body, { idempotencyKey })` | `POST /api/v1/queues/{queueId}/events` | required |
| `relay.events.get(eventId)` | `GET /api/v1/events/{eventId}` | — |
| `relay.events.get(eventId, { attempts: true })` | `GET …?attempts=1` | — |
| `relay.events.result(eventId, body, { idempotencyKey })` | `POST /api/v1/events/{eventId}/result` | required |
| `relay.events.checkpoints(eventId, checkpoints)` | `POST /api/v1/events/{eventId}/checkpoints` | — |
| `relay.schedules.list(queueId)` | `GET /api/v1/queues/{queueId}/schedules` | — |
| `relay.schedules.create(queueId, body)` | `POST /api/v1/queues/{queueId}/schedules` | — |
| `relay.schedules.delete(scheduleId)` | `DELETE /api/v1/schedules/{scheduleId}` | — |

Request and response shapes come from `relay-types` and are re-exported from `relay-sdk`.

### Events

```ts
// Delay delivery (at most one of deliver_at / delay_seconds; omit both for ASAP).
await relay.events.submit(
  queueId,
  { event_type: "order.created", event: { id: "ord_1" }, delay_seconds: 60 },
  { idempotencyKey: "order-ord_1" },
);

const event = await relay.events.get(accepted.event_id);
const withAttempts = await relay.events.get(accepted.event_id, { attempts: true });
// withAttempts.attempts, withAttempts.checkpoints

await relay.events.result(
  accepted.event_id,
  { status: "completed", result: { provider_id: "msg_1" } },
  { idempotencyKey: "result-ord_1" },
);

await relay.events.checkpoints(accepted.event_id, [
  { tag: "received", at: new Date().toISOString() },
  { tag: "done" },
]);
```

`send_message` events must carry only `{ notification_id }` in `event`.

### Schedules

```ts
const { schedules, limit } = await relay.schedules.list(queueId);

const { schedule } = await relay.schedules.create(queueId, {
  name: "daily-digest",
  cron: "0 9 * * *",
  timezone: "America/Sao_Paulo",
  event_type: "digest.run",
  event: { kind: "daily" },
});

await relay.schedules.delete(schedule.id);
```

`enabled` on create is accepted by the API but not stored; new schedules always start enabled.

## Ed25519 or KMS

Pass a PKCS#8 Ed25519 `privateKeyPem`, or a `sign` hook. The hook receives those raw UTF-8 bytes and returns the full header value: `sha256=` plus 64 lowercase hex characters, or `ed25519=` plus standard base64 of the 64-byte signature.

```ts
const relay = createRelay({
  apiKey,
  sign: async (bytes) => {
    const signature = await kmsSignEd25519(bytes); // 64 raw bytes
    return "ed25519=" + Buffer.from(signature).toString("base64");
  },
});
```

Register the matching SPKI public key on the queue before the first `ed25519=` call. `request_public_key_pem` must be a public key; a private key PEM is rejected before the request is sent.

## Webhooks

```ts
import { verifyWebhook } from "relay-sdk";

const delivery = verifyWebhook({
  apiKey,
  secret,
  rawBody, // exact bytes, before JSON.parse
  headers: req.headers,
  deliveryPublicKeyPem, // set when webhook_auth_mode is "ed25519"
});

delivery.eventId;
delivery.attempt;
delivery.idempotencyKey;
```

`Idempotency-Key` is unsigned. A request with that header swapped still verifies. Dedupe on the signed pair `(event_id, attempt)` as well as on the idempotency key. When `deliveryPublicKeyPem` is set, the Ed25519 signature covers `v1.{timestamp}.{eventId}.{sha256_hex(body)}` and the timestamp must be within ±300 seconds. HMAC-only deliveries have no timestamp.

A header value that arrives as a `string[]` must contain exactly one entry.

## Errors

Failed `/api/v1` calls throw `RelayError` (`status`, `message`, optional `code`, `requestId`, `retryAfter`, `issues`, quota fields). Webhook verification failures throw `WebhookVerificationError`.

## Fetch and base URL

`baseUrl` defaults to `https://relay.surfih.com` (`DEFAULT_BASE_URL`). Pass it only to target another origin (local, staging).

Every call sets `redirect: "error"`. A custom `fetch` must honor that and must not follow redirects.

When set, `baseUrl` is parsed with `new URL`. It must be `https`, or `http` for `localhost`, `127.0.0.1`, or `::1`. Other `http` origins need `allowInsecureHttp: true`. Userinfo, query, hash, and a non-root path are rejected.
