import { createHmac, generateKeyPairSync, verify } from "node:crypto";
import { createServer, type IncomingMessage } from "node:http";
import type { AddressInfo } from "node:net";
import assert from "node:assert/strict";
import { test } from "node:test";
import {
  DEFAULT_BASE_URL,
  RelayError,
  createRelay,
  type Event,
  type EventWithAttempts,
  type Relay,
  type RelayFetch,
} from "../src/index.js";

const API_KEY = "ak_live_test";
const SECRET = "cs_live_test_secret_value";
const NOW = 1_700_000_000_000;

function client(fetchImpl: RelayFetch, baseUrl = "https://relay.example.com"): Relay {
  return createRelay({
    baseUrl,
    apiKey: API_KEY,
    secret: SECRET,
    now: () => NOW,
    fetch: fetchImpl,
  });
}

function mockFetch(status: number, body: string, responseHeaders: Record<string, string> = {}) {
  const calls: { url: URL; init: RequestInit }[] = [];
  const fetchImpl: RelayFetch = async (url, init) => {
    calls.push({ url, init });
    return new Response(body, { status, headers: responseHeaders });
  };
  return { calls, fetchImpl };
}

function header(init: RequestInit, name: string): string | null {
  return new Headers(init.headers).get(name);
}

function bodyText(init: RequestInit): string | undefined {
  if (init.body === undefined || init.body === null) return undefined;
  if (init.body instanceof Uint8Array) return new TextDecoder().decode(init.body);
  throw new Error("unexpected body type");
}

function expectedHmac(method: string, path: string, raw: string): string {
  const message = `${API_KEY}.1700000000.${method}.${path}.${raw}`;
  return `sha256=${createHmac("sha256", SECRET).update(message).digest("hex")}`;
}

function assertNoSecrets(err: unknown, secrets: readonly string[]): void {
  const error = err as Error & Record<string, unknown>;
  const blob = [error.message, error.stack ?? "", JSON.stringify(error, Object.getOwnPropertyNames(error))].join("\n");
  for (const secret of secrets) assert.equal(blob.includes(secret), false);
}

test("create queue accepts 200 and 201 and signs the stringified body once", async () => {
  const payload = { name: "messages", webhook_url: "https://example.com/hook" };
  const json = JSON.stringify(payload);
  for (const status of [200, 201]) {
    const { calls, fetchImpl } = mockFetch(status, JSON.stringify({ created: status === 201, queue: { id: "que_1" } }));
    const original = JSON.stringify;
    let callsToStringify = 0;
    JSON.stringify = ((value: unknown, replacer?: unknown, space?: unknown) => {
      callsToStringify += 1;
      return original(value, replacer as never, space as never);
    }) as typeof JSON.stringify;
    try {
      const relay = client(fetchImpl);
      const result = await relay.queues.create(payload, { idempotencyKey: "  queue-messages  " });
      assert.equal(result.created, status === 201);
    } finally {
      JSON.stringify = original;
    }
    assert.equal(callsToStringify, 1);
    const init = calls[0]?.init;
    assert.ok(init);
    assert.equal(init.redirect, "error");
    assert.equal(bodyText(init), json);
    assert.equal(header(init, "content-type"), "application/json");
    assert.equal(header(init, "idempotency-key"), "queue-messages");
    assert.equal(header(init, "x-api-key"), API_KEY);
    assert.equal(header(init, "x-timestamp"), "1700000000");
    assert.equal(header(init, "x-payload-signature"), expectedHmac("POST", "/api/v1/queues", json));
    assert.equal(calls[0]?.url.href, "https://relay.example.com/api/v1/queues");
  }
});

test("submit accepts only 202", async () => {
  const body = { event_type: "order.created", event: { id: "ord_1" } };
  const json = JSON.stringify(body);
  const ok = mockFetch(202, JSON.stringify({ event_id: "evt_1", server_status: "idle", client_status: null, deliver_at: null }));
  const relay = client(ok.fetchImpl);
  const accepted = await relay.events.submit("que_1", body, { idempotencyKey: "order-1" });
  assert.equal(accepted.event_id, "evt_1");
  const init = ok.calls[0]?.init;
  assert.ok(init);
  assert.equal(header(init, "x-payload-signature"), expectedHmac("POST", "/api/v1/queues/que_1/events", json));

  for (const status of [200, 201]) {
    const bad = mockFetch(status, JSON.stringify({ event_id: "evt_1" }));
    await assert.rejects(() => client(bad.fetchImpl).events.submit("que_1", body, { idempotencyKey: "order-1" }), (err: unknown) => {
      assert.equal(err instanceof RelayError, true);
      assert.equal((err as RelayError).status, status);
      return true;
    });
  }
});

test("GET signs an empty body, omits content-type, and attempts=1 is part of the signature", async () => {
  const event = mockFetch(200, JSON.stringify({ event_id: "evt_1" }));
  const withAttempts = mockFetch(200, JSON.stringify({ event_id: "evt_1", attempts: [], checkpoints: [] }));
  const relay = client(async (url, init) => {
    const target = url.searchParams.get("attempts") === "1" ? withAttempts.fetchImpl : event.fetchImpl;
    return target(url, init);
  });
  const plain: Event = await relay.events.get("evt_1");
  const full: EventWithAttempts = await relay.events.get("evt_1", { attempts: true });
  assert.equal(plain.event_id, "evt_1");
  assert.equal(full.attempts.length, 0);

  const getInit = event.calls[0]?.init;
  assert.ok(getInit);
  assert.equal(getInit.body, undefined);
  assert.equal(header(getInit, "content-type"), null);
  assert.equal(header(getInit, "idempotency-key"), null);
  assert.equal(header(getInit, "x-payload-signature"), expectedHmac("GET", "/api/v1/events/evt_1", ""));
  assert.equal(event.calls[0]?.url.href, "https://relay.example.com/api/v1/events/evt_1");

  const attemptInit = withAttempts.calls[0]?.init;
  assert.ok(attemptInit);
  assert.equal(attemptInit.body, undefined);
  assert.equal(header(attemptInit, "content-type"), null);
  assert.equal(
    header(attemptInit, "x-payload-signature"),
    expectedHmac("GET", "/api/v1/events/evt_1?attempts=1", ""),
  );
  const attemptUrl = withAttempts.calls[0]?.url;
  assert.ok(attemptUrl);
  assert.equal(attemptUrl.pathname + attemptUrl.search, "/api/v1/events/evt_1?attempts=1");
});

test("idempotency key is required, trimmed, and omitted on reads, checkpoints, and schedules", async () => {
  const calls: { url: URL; init: RequestInit }[] = [];
  const fetchImpl: RelayFetch = async (url, init) => {
    calls.push({ url, init });
    if (init.method === "POST" && url.pathname.endsWith("/schedules")) {
      return new Response(JSON.stringify({ schedule: { id: "sch_1" } }), { status: 201 });
    }
    return new Response("{}", { status: 200 });
  };
  const relay = client(fetchImpl);

  await assert.rejects(() => relay.events.submit("que_1", { event_type: "t" }, { idempotencyKey: "   " }), /must not be empty/);
  await assert.rejects(
    () => relay.events.submit("que_1", { event_type: "t" }, { idempotencyKey: "a".repeat(201) }),
    /at most 200 characters/,
  );
  await assert.rejects(
    () => relay.queues.create({ name: "q", webhook_url: "https://example.com/h" }, { idempotencyKey: "a\nb" }),
    /printable ASCII/,
  );

  await relay.events.get("evt_1");
  await relay.events.checkpoints("evt_1", [{ tag: "received" }]);
  await relay.events.result("evt_1", { status: "completed", result: { ok: true } }, { idempotencyKey: "result-1" });
  await relay.schedules.list("que_1");
  await relay.schedules.create("que_1", { name: "hourly", cron: "0 * * * *", event_type: "tick", event: {} });
  await relay.schedules.delete("sch_1");

  const byPath = new Map(calls.map((entry) => [`${entry.init.method} ${entry.url.pathname}`, entry]));
  assert.equal(header(byPath.get("GET /api/v1/events/evt_1")!.init, "idempotency-key"), null);
  assert.equal(header(byPath.get("POST /api/v1/events/evt_1/checkpoints")!.init, "idempotency-key"), null);
  assert.equal(header(byPath.get("POST /api/v1/events/evt_1/result")!.init, "idempotency-key"), "result-1");
  assert.equal(header(byPath.get("GET /api/v1/queues/que_1/schedules")!.init, "idempotency-key"), null);
  assert.equal(header(byPath.get("POST /api/v1/queues/que_1/schedules")!.init, "idempotency-key"), null);
  assert.equal(header(byPath.get("DELETE /api/v1/schedules/sch_1")!.init, "idempotency-key"), null);
  assert.equal(header(byPath.get("DELETE /api/v1/schedules/sch_1")!.init, "content-type"), null);
  assert.equal(byPath.get("DELETE /api/v1/schedules/sch_1")!.init.body, undefined);
  assert.equal(
    header(byPath.get("DELETE /api/v1/schedules/sch_1")!.init, "x-payload-signature"),
    expectedHmac("DELETE", "/api/v1/schedules/sch_1", ""),
  );
});

test("maps 409 existing_event_id and 429 retry-after without copying extra fields", async () => {
  const conflict = mockFetch(
    409,
    JSON.stringify({
      error: {
        message: "Idempotency-Key reused with different payload",
        existing_event_id: "evt_existing",
        secret_debug: SECRET,
      },
    }),
    { "x-request-id": "req_9" },
  );
  await assert.rejects(
    () => client(conflict.fetchImpl).events.submit("que_1", { event_type: "t" }, { idempotencyKey: "order-1" }),
    (err: unknown) => {
      assert.equal(err instanceof RelayError, true);
      const relayError = err as RelayError;
      assert.equal(relayError.status, 409);
      assert.equal(relayError.existingEventId, "evt_existing");
      assert.equal(relayError.requestId, "req_9");
      assert.equal(relayError.message, "Idempotency-Key reused with different payload");
      assertNoSecrets(err, [SECRET]);
      return true;
    },
  );

  const limited = mockFetch(429, JSON.stringify({ error: { message: "Too many requests", code: "rate_limited" } }), {
    "retry-after": "30",
  });
  await assert.rejects(
    () => client(limited.fetchImpl).events.submit("que_1", { event_type: "t" }, { idempotencyKey: "order-1" }),
    (err: unknown) => {
      const relayError = err as RelayError;
      assert.equal(relayError.status, 429);
      assert.equal(relayError.code, "rate_limited");
      assert.equal(relayError.retryAfter, 30);
      assert.equal(relayError.message, "Too many requests");
      return true;
    },
  );
});

test("caps the server message at 500 code points and does not echo non-JSON bodies", async () => {
  const marker = "SECRET_TAIL_MARKER";
  const huge = mockFetch(400, JSON.stringify({ error: { message: "😀".repeat(500) + marker } }));
  await assert.rejects(
    () => client(huge.fetchImpl).events.get("evt_1"),
    (err: unknown) => {
      const relayError = err as RelayError;
      assert.equal([...relayError.message].length, 500);
      assert.equal(relayError.message.includes(marker), false);
      assert.equal(relayError.message.length, 1000);
      return true;
    },
  );

  const junk = mockFetch(500, `not-json ${SECRET}`);
  await assert.rejects(() => client(junk.fetchImpl).events.get("evt_1"), (err: unknown) => {
    const relayError = err as RelayError;
    assert.equal(relayError.message, "Relay request failed");
    assertNoSecrets(err, [SECRET]);
    return true;
  });

  const badSuccess = mockFetch(200, `not-json ${SECRET}`);
  await assert.rejects(() => client(badSuccess.fetchImpl).events.get("evt_1"), (err: unknown) => {
    assert.equal((err as RelayError).message, "Relay response was not valid JSON");
    assertNoSecrets(err, [SECRET]);
    return true;
  });
});

test("rejects a private key PEM before fetch", async () => {
  const marker = "PRIVMARKERBYTES123";
  const pem = `-----BEGIN RSA PRIVATE KEY-----\n${marker}\n-----END RSA PRIVATE KEY-----\n`;
  let called = 0;
  const fetchImpl: RelayFetch = async () => {
    called += 1;
    return new Response("{}", { status: 201 });
  };
  const relay = client(fetchImpl);
  await assert.rejects(
    () =>
      relay.queues.create(
        { name: "q", webhook_url: "https://example.com/h", request_public_key_pem: pem },
        { idempotencyKey: "queue-1" },
      ),
    (err: unknown) => {
      assert.equal(err instanceof TypeError, true);
      assert.equal((err as TypeError).message, "request_public_key_pem must be a public key");
      assertNoSecrets(err, [marker, pem]);
      return true;
    },
  );
  assert.equal(called, 0);
});

test("allows a public key PEM and encodes path segments", async () => {
  const calls: { url: URL; init: RequestInit }[] = [];
  const fetchImpl: RelayFetch = async (url, init) => {
    calls.push({ url, init });
    if (url.pathname === "/api/v1/queues") {
      return new Response(JSON.stringify({ created: true, queue: { id: "que_1" } }), { status: 201 });
    }
    return new Response(
      JSON.stringify({ event_id: "evt_1", server_status: "idle", client_status: null, deliver_at: null }),
      { status: 202 },
    );
  };
  const relay = client(fetchImpl);
  await relay.queues.create(
    {
      name: "q",
      webhook_url: "https://example.com/h",
      request_public_key_pem: "-----BEGIN PUBLIC KEY-----\nMCowBQYDK2VwAyEA\n-----END PUBLIC KEY-----\n",
    },
    { idempotencyKey: "queue-1" },
  );
  await relay.events.submit("a/b", { event_type: "t" }, { idempotencyKey: "k" });
  assert.equal(calls[1]?.url.pathname, "/api/v1/queues/a%2Fb/events");
});

test("rejects paths that escape the origin before fetch", async () => {
  let called = 0;
  const fetchImpl: RelayFetch = async () => {
    called += 1;
    return new Response("{}", { status: 202 });
  };
  const relay = client(fetchImpl);
  await assert.rejects(() => relay.events.submit("..", { event_type: "t" }, { idempotencyKey: "k" }), /escaped the relay origin/);
  assert.equal(called, 0);
});

test("defaults baseUrl to the production Relay origin", async () => {
  assert.equal(DEFAULT_BASE_URL, "https://relay.surfih.com");
  const { calls, fetchImpl } = mockFetch(200, JSON.stringify({ created: true, queue: { id: "que_1" } }));
  const relay = createRelay({
    apiKey: API_KEY,
    secret: SECRET,
    now: () => NOW,
    fetch: fetchImpl,
  });
  await relay.queues.create(
    { name: "messages", webhook_url: "https://example.com/hook" },
    { idempotencyKey: "queue-messages" },
  );
  assert.equal(calls[0]?.url.href, "https://relay.surfih.com/api/v1/queues");
});

test("rejects insecure, credentialed, and pathed base URLs", () => {
  const password = "s3cret-password";
  const common = { apiKey: API_KEY, secret: SECRET };
  assert.throws(() => createRelay({ ...common, baseUrl: "http://example.com" }), /must use https/);
  assert.throws(() => createRelay({ ...common, baseUrl: "ftp://example.com" }), /must use https/);
  assert.throws(() => createRelay({ ...common, baseUrl: "/relative" }), /absolute http\(s\) URL/);
  assert.throws(() => createRelay({ ...common, baseUrl: "https://example.com/api" }), /must not include a path/);
  assert.throws(() => createRelay({ ...common, baseUrl: "https://example.com?x=1" }), /query or hash/);
  assert.throws(() => createRelay({ ...common, baseUrl: "https://example.com#h" }), /query or hash/);
  assert.throws(
    () => createRelay({ ...common, baseUrl: `https://user:${password}@example.com` }),
    (err: unknown) => {
      assert.match((err as Error).message, /credentials/);
      assertNoSecrets(err, [password]);
      return true;
    },
  );
  assert.doesNotThrow(() => createRelay({ ...common, baseUrl: "http://localhost:8787" }));
  assert.doesNotThrow(() => createRelay({ ...common, baseUrl: "http://127.0.0.1:8787" }));
  assert.doesNotThrow(() => createRelay({ ...common, baseUrl: "http://[::1]:8787" }));
  assert.doesNotThrow(() => createRelay({ ...common, baseUrl: "http://example.com", allowInsecureHttp: true }));
  assert.throws(
    () => createRelay({ ...common, baseUrl: "https://relay.example.com", secret: SECRET, privateKeyPem: "pem" }),
    /exactly one of secret, privateKeyPem, or sign/,
  );
  assert.throws(() => createRelay({ baseUrl: "https://relay.example.com", apiKey: API_KEY }), /exactly one/);
  assert.throws(() => createRelay({ baseUrl: "https://relay.example.com", apiKey: "bad\nkey", secret: SECRET }), /printable ASCII/);
});

test("Ed25519 requests verify and custom sign is sent as validated", async () => {
  const { privateKey, publicKey } = generateKeyPairSync("ed25519");
  const exportedPem = privateKey.export({ type: "pkcs8", format: "pem" });
  if (typeof exportedPem !== "string") throw new Error("expected PEM text");
  const privatePem = exportedPem;
  const { calls, fetchImpl } = mockFetch(200, JSON.stringify({ event_id: "evt_1" }));
  const relay = createRelay({
    baseUrl: "https://relay.example.com",
    apiKey: API_KEY,
    privateKeyPem: privatePem,
    now: () => NOW,
    fetch: fetchImpl,
  });
  await relay.events.get("evt_1");
  const signature = header(calls[0]!.init, "x-payload-signature");
  assert.ok(signature);
  assert.ok(signature.startsWith("ed25519="));
  assert.equal(header(calls[0]!.init, "content-type"), null);
  const raw = Buffer.from(signature.slice("ed25519=".length), "base64");
  const message = Buffer.from(`${API_KEY}.1700000000.GET./api/v1/events/evt_1.`);
  assert.equal(verify(null, message, publicKey, raw), true);

  let seen = "";
  const custom = mockFetch(200, JSON.stringify({ event_id: "evt_1" }));
  const hooked = createRelay({
    baseUrl: "https://relay.example.com",
    apiKey: API_KEY,
    now: () => NOW,
    fetch: custom.fetchImpl,
    sign: (bytes) => {
      seen = new TextDecoder().decode(bytes);
      return `sha256=${createHmac("sha256", SECRET).update(bytes).digest("hex")}`;
    },
  });
  await hooked.events.get("evt_1");
  assert.equal(seen, `${API_KEY}.1700000000.GET./api/v1/events/evt_1.`);
  assert.equal(header(custom.calls[0]!.init, "x-payload-signature"), expectedHmac("GET", "/api/v1/events/evt_1", ""));

  const bad = "not-a-signature-SECRET";
  let fetched = 0;
  const refusing = createRelay({
    baseUrl: "https://relay.example.com",
    apiKey: API_KEY,
    now: () => NOW,
    fetch: async () => {
      fetched += 1;
      return new Response("{}", { status: 200 });
    },
    sign: () => bad,
  });
  await assert.rejects(() => refusing.events.get("evt_1"), (err: unknown) => {
    assert.equal((err as TypeError).message, "sign() must return sha256=<64 lowercase hex> or ed25519=<standard base64 of 64 bytes>");
    assertNoSecrets(err, [bad, SECRET]);
    return true;
  });
  assert.equal(fetched, 0);
});

test("passes redirect error and abort signal through fetch", async () => {
  const { calls, fetchImpl } = mockFetch(200, JSON.stringify({ event_id: "evt_1" }));
  const controller = new AbortController();
  await client(fetchImpl).events.get("evt_1", { signal: controller.signal });
  assert.equal(calls[0]?.init.redirect, "error");
  assert.equal(calls[0]?.init.signal, controller.signal);
});

test("real fetch posts the signed bytes and refuses redirects", async () => {
  const payload = { name: "messages", webhook_url: "https://example.com/hook" };
  const json = JSON.stringify(payload);
  await withServer(async (req, res) => {
    const raw = await readIncoming(req);
    assert.equal(req.headers["content-type"], "application/json");
    assert.equal(req.headers["idempotency-key"], "queue-1");
    assert.equal(raw.toString("utf8"), json);
    const signed = `${API_KEY}.${req.headers["x-timestamp"]}.POST.${req.url}.${raw.toString("utf8")}`;
    const mac = `sha256=${createHmac("sha256", SECRET).update(signed).digest("hex")}`;
    assert.equal(req.headers["x-payload-signature"], mac);
    assert.equal(JSON.stringify(req.headers).includes(SECRET), false);
    res.writeHead(201, { "content-type": "application/json" });
    res.end('{"created":true,"queue":{"id":"que_1"}}');
  }, async (baseUrl) => {
    const relay = createRelay({ baseUrl, apiKey: API_KEY, secret: SECRET, now: () => NOW });
    const created = await relay.queues.create(payload, { idempotencyKey: "queue-1" });
    assert.equal(created.created, true);
  });

  let hits = 0;
  await withServer((_req, res) => {
    hits += 1;
    res.writeHead(302, { location: "/stolen" });
    res.end();
  }, async (baseUrl) => {
    const relay = createRelay({ baseUrl, apiKey: API_KEY, secret: SECRET, now: () => NOW });
    await assert.rejects(
      () => relay.queues.create(payload, { idempotencyKey: "queue-1" }),
      (err: unknown) => {
        assert.equal(err instanceof RelayError, false);
        assertNoSecrets(err, [SECRET]);
        return true;
      },
    );
  });
  assert.equal(hits, 1);
});

async function withServer(
  handler: (req: IncomingMessage, res: import("node:http").ServerResponse) => void | Promise<void>,
  run: (baseUrl: string) => Promise<void>,
): Promise<void> {
  let serverError: unknown;
  const server = createServer((req, res) => {
    void Promise.resolve(handler(req, res)).catch((err: unknown) => {
      serverError = err;
      if (!res.headersSent) res.writeHead(500);
      res.end();
    });
  });
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const address = server.address() as AddressInfo;
  let failure: unknown;
  try {
    await run(`http://127.0.0.1:${address.port}`);
  } catch (err) {
    failure = err;
  } finally {
    await new Promise<void>((resolve, reject) => server.close((err) => (err ? reject(err) : resolve())));
  }
  if (serverError) throw serverError;
  if (failure) throw failure;
}

function readIncoming(req: IncomingMessage): Promise<Buffer> {
  return new Promise((resolve, reject) => {
    const chunks: Buffer[] = [];
    req.on("data", (chunk: Buffer | string) => chunks.push(Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk)));
    req.on("end", () => resolve(Buffer.concat(chunks)));
    req.on("error", reject);
  });
}
