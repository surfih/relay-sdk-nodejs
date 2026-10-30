import { paths } from "relay-types";
import type {
  AcceptedEventResponse,
  CheckpointInput,
  CreateQueueRequest,
  CreateQueueResponse,
  CreateScheduleRequest,
  DeletedScheduleResponse,
  Event,
  EventResultResponse,
  EventWithAttempts,
  PostCheckpointsResponse,
  PostEventResultRequest,
  ScheduleListResponse,
  ScheduleResponse,
  SubmitEventRequest,
} from "relay-types";
import { assertRelayOrigin } from "./origin.js";
import { signedRequest, type RelayFetch, type SignedCall } from "./request.js";
import {
  assertApiKey,
  assertPublicRequestKey,
  assertSecret,
  customSigner,
  ed25519Signer,
  hmacSigner,
  type SignFn,
  type Signer,
} from "./sign.js";

export type { RelayFetch, SignFn };

/** Production Relay origin used when `CreateRelayOptions.baseUrl` is omitted. */
export const DEFAULT_BASE_URL = "https://relay.surfih.com";

/** `now` returns milliseconds since the Unix epoch, the same as `Date.now`. */
export interface CreateRelayOptions {
  /**
   * Relay origin. Defaults to {@link DEFAULT_BASE_URL}.
   * Parsed with `new URL`; must be `https`, or `http` for loopback unless `allowInsecureHttp`.
   */
  baseUrl?: string;
  apiKey: string;
  /** HMAC key (`cs_live_…`). Mutually exclusive with `privateKeyPem` and `sign`. */
  secret?: string;
  /** PKCS#8 Ed25519 private key. Mutually exclusive with `secret` and `sign`. */
  privateKeyPem?: string;
  /**
   * Signs the raw UTF-8 bytes of `apiKey.timestamp.METHOD.pathAndQuery.rawBody`.
   * Return `sha256=<64 lowercase hex>` or `ed25519=<standard base64 of 64 bytes>`.
   */
  sign?: SignFn;
  /** Milliseconds since the Unix epoch. Defaults to `Date.now`. */
  now?: () => number;
  /**
   * Replacement for global `fetch`. Every call passes `redirect: "error"`.
   * The implementation must not follow redirects.
   */
  fetch?: RelayFetch;
  /** Allow `http://` to a non-loopback host. Loopback http is always allowed. */
  allowInsecureHttp?: boolean;
}

export interface RequestOptions {
  signal?: AbortSignal;
}

export interface IdempotentOptions extends RequestOptions {
  idempotencyKey: string;
}

export interface GetEventOptions extends RequestOptions {
  /** `true` sends `?attempts=1` and returns attempts plus checkpoints. */
  attempts?: boolean;
}

export interface RelayQueues {
  create(body: CreateQueueRequest, options: IdempotentOptions): Promise<CreateQueueResponse>;
}

export interface RelayEvents {
  submit(queueId: string, body: SubmitEventRequest, options: IdempotentOptions): Promise<AcceptedEventResponse>;
  get(eventId: string, options: GetEventOptions & { attempts: true }): Promise<EventWithAttempts>;
  get(eventId: string, options?: GetEventOptions): Promise<Event>;
  result(eventId: string, body: PostEventResultRequest, options: IdempotentOptions): Promise<EventResultResponse>;
  checkpoints(
    eventId: string,
    checkpoints: readonly CheckpointInput[],
    options?: RequestOptions,
  ): Promise<PostCheckpointsResponse>;
}

export interface RelaySchedules {
  list(queueId: string, options?: RequestOptions): Promise<ScheduleListResponse>;
  create(queueId: string, body: CreateScheduleRequest, options?: RequestOptions): Promise<ScheduleResponse>;
  delete(scheduleId: string, options?: RequestOptions): Promise<DeletedScheduleResponse>;
}

export interface Relay {
  queues: RelayQueues;
  events: RelayEvents;
  schedules: RelaySchedules;
}

interface Transport {
  origin: string;
  apiKey: string;
  sign: Signer;
  now: () => number;
  fetch: RelayFetch;
}

/**
 * Client for `/api/v1`. Signing headers are applied internally.
 * Pass exactly one of `secret`, `privateKeyPem`, or `sign`.
 *
 * `baseUrl` defaults to {@link DEFAULT_BASE_URL}. When set, it is parsed with `new URL`
 * and must be `https`, or `http` for `localhost` / `127.0.0.1` / `::1`, unless
 * `allowInsecureHttp` is set. Credentials, query, hash, and a non-root path are rejected.
 * Each request is built with `new URL(pathAndQuery, origin)` and must not escape that origin.
 * `redirect: "error"` is set on every fetch.
 */
export function createRelay(options: CreateRelayOptions): Relay {
  const apiKey = assertApiKey(options.apiKey);
  const origin = assertRelayOrigin(options.baseUrl ?? DEFAULT_BASE_URL, options.allowInsecureHttp === true);
  const sign = resolveSigner(options);
  if (options.now !== undefined && typeof options.now !== "function") {
    throw new TypeError("now must be a function");
  }
  if (options.fetch !== undefined && typeof options.fetch !== "function") {
    throw new TypeError("fetch must be a function");
  }
  const now = options.now ?? Date.now;
  const fetchImpl: RelayFetch =
    options.fetch ??
    ((input, init) => {
      if (typeof globalThis.fetch !== "function") {
        throw new TypeError("fetch is not available");
      }
      return globalThis.fetch(input, init);
    });
  const transport: Transport = { origin, apiKey, sign, now, fetch: fetchImpl };
  return {
    queues: new QueuesApi(transport),
    events: new EventsApi(transport),
    schedules: new SchedulesApi(transport),
  };
}

function resolveSigner(options: CreateRelayOptions): Signer {
  const selected = [options.secret !== undefined, options.privateKeyPem !== undefined, options.sign !== undefined];
  const count = selected.filter(Boolean).length;
  if (count !== 1) {
    throw new TypeError("createRelay requires exactly one of secret, privateKeyPem, or sign");
  }
  if (options.secret !== undefined) return hmacSigner(assertSecret(options.secret));
  if (options.privateKeyPem !== undefined) return ed25519Signer(options.privateKeyPem);
  return customSigner(options.sign as SignFn);
}

function call(input: SignedCall): SignedCall {
  const next: SignedCall = {
    method: input.method,
    pathAndQuery: input.pathAndQuery,
    successStatuses: input.successStatuses,
  };
  if (input.jsonBody !== undefined) next.jsonBody = input.jsonBody;
  if (input.idempotencyKey !== undefined) next.idempotencyKey = input.idempotencyKey;
  if (input.signal !== undefined) next.signal = input.signal;
  return next;
}

function assertId(value: string, label: "queueId" | "eventId" | "scheduleId"): void {
  if (typeof value !== "string" || value.length === 0) {
    throw new TypeError(`${label} must be a non-empty string`);
  }
}

class QueuesApi implements RelayQueues {
  constructor(private readonly transport: Transport) {}

  async create(body: CreateQueueRequest, options: IdempotentOptions): Promise<CreateQueueResponse> {
    assertPublicRequestKey(body.request_public_key_pem);
    return signedRequest<CreateQueueResponse>(
      this.transport,
      call({
        method: "POST",
        pathAndQuery: paths.createQueue,
        jsonBody: body,
        idempotencyKey: options.idempotencyKey,
        successStatuses: [200, 201],
        ...(options.signal !== undefined ? { signal: options.signal } : {}),
      }),
    );
  }
}

class EventsApi implements RelayEvents {
  constructor(private readonly transport: Transport) {}

  async submit(queueId: string, body: SubmitEventRequest, options: IdempotentOptions): Promise<AcceptedEventResponse> {
    assertId(queueId, "queueId");
    return signedRequest<AcceptedEventResponse>(
      this.transport,
      call({
        method: "POST",
        pathAndQuery: paths.submitEvent(queueId),
        jsonBody: body,
        idempotencyKey: options.idempotencyKey,
        successStatuses: [202],
        ...(options.signal !== undefined ? { signal: options.signal } : {}),
      }),
    );
  }

  get(eventId: string, options: GetEventOptions & { attempts: true }): Promise<EventWithAttempts>;
  get(eventId: string, options?: GetEventOptions): Promise<Event>;
  async get(eventId: string, options?: GetEventOptions): Promise<Event | EventWithAttempts> {
    assertId(eventId, "eventId");
    const path = paths.getEvent(eventId);
    const attempts = options?.attempts === true;
    const pathAndQuery = attempts ? `${path}?attempts=1` : path;
    const signal = options?.signal;
    if (attempts) {
      return signedRequest<EventWithAttempts>(
        this.transport,
        call({
          method: "GET",
          pathAndQuery,
          successStatuses: [200],
          ...(signal !== undefined ? { signal } : {}),
        }),
      );
    }
    return signedRequest<Event>(
      this.transport,
      call({
        method: "GET",
        pathAndQuery,
        successStatuses: [200],
        ...(signal !== undefined ? { signal } : {}),
      }),
    );
  }

  async result(eventId: string, body: PostEventResultRequest, options: IdempotentOptions): Promise<EventResultResponse> {
    assertId(eventId, "eventId");
    return signedRequest<EventResultResponse>(
      this.transport,
      call({
        method: "POST",
        pathAndQuery: paths.postEventResult(eventId),
        jsonBody: body,
        idempotencyKey: options.idempotencyKey,
        successStatuses: [200],
        ...(options.signal !== undefined ? { signal: options.signal } : {}),
      }),
    );
  }

  async checkpoints(
    eventId: string,
    checkpoints: readonly CheckpointInput[],
    options?: RequestOptions,
  ): Promise<PostCheckpointsResponse> {
    assertId(eventId, "eventId");
    return signedRequest<PostCheckpointsResponse>(
      this.transport,
      call({
        method: "POST",
        pathAndQuery: paths.postCheckpoints(eventId),
        jsonBody: { checkpoints },
        successStatuses: [200],
        ...(options?.signal !== undefined ? { signal: options.signal } : {}),
      }),
    );
  }
}

class SchedulesApi implements RelaySchedules {
  constructor(private readonly transport: Transport) {}

  async list(queueId: string, options?: RequestOptions): Promise<ScheduleListResponse> {
    assertId(queueId, "queueId");
    return signedRequest<ScheduleListResponse>(
      this.transport,
      call({
        method: "GET",
        pathAndQuery: paths.listSchedules(queueId),
        successStatuses: [200],
        ...(options?.signal !== undefined ? { signal: options.signal } : {}),
      }),
    );
  }

  async create(queueId: string, body: CreateScheduleRequest, options?: RequestOptions): Promise<ScheduleResponse> {
    assertId(queueId, "queueId");
    return signedRequest<ScheduleResponse>(
      this.transport,
      call({
        method: "POST",
        pathAndQuery: paths.createSchedule(queueId),
        jsonBody: body,
        successStatuses: [201],
        ...(options?.signal !== undefined ? { signal: options.signal } : {}),
      }),
    );
  }

  async delete(scheduleId: string, options?: RequestOptions): Promise<DeletedScheduleResponse> {
    assertId(scheduleId, "scheduleId");
    return signedRequest<DeletedScheduleResponse>(
      this.transport,
      call({
        method: "DELETE",
        pathAndQuery: paths.deleteSchedule(scheduleId),
        successStatuses: [200],
        ...(options?.signal !== undefined ? { signal: options.signal } : {}),
      }),
    );
  }
}
