import {
  API_KEY_HEADER,
  CONTENT_TYPE_HEADER,
  IDEMPOTENCY_KEY_HEADER,
  JSON_CONTENT_TYPE,
  PAYLOAD_SIGNATURE_HEADER,
  REQUEST_ID_HEADER,
  RETRY_AFTER_HEADER,
  TIMESTAMP_HEADER,
} from "relay-types";
import {
  RelayError,
  invalidJsonMessage,
  readRequestId,
  readRetryAfter,
  toRelayError,
} from "./errors.js";
import { resolveRelayUrl } from "./origin.js";
import { assertIdempotencyKey, assertSignatureHeader, signingBytes, unixSeconds, type Signer } from "./sign.js";

/** Custom fetch must honor `redirect: "error"` and must not follow redirects. */
export type RelayFetch = (input: URL, init: RequestInit) => Promise<Response>;

export interface RelayTransport {
  origin: string;
  apiKey: string;
  sign: Signer;
  now: () => number;
  fetch: RelayFetch;
}

export interface SignedCall {
  method: "GET" | "POST" | "DELETE";
  pathAndQuery: string;
  successStatuses: readonly number[];
  jsonBody?: unknown;
  idempotencyKey?: string;
  signal?: AbortSignal;
}

const EMPTY_BODY = new Uint8Array(0);

/**
 * Sign `apiKey.timestamp.METHOD.pathAndQuery.rawBody` and send those exact bytes.
 * GET and DELETE use an empty body, omit `content-type`, and the signing string ends with `.`.
 * Every call sets `redirect: "error"`.
 */
export async function signedRequest<T>(transport: RelayTransport, call: SignedCall): Promise<T> {
  const idempotencyKey =
    call.idempotencyKey === undefined ? undefined : assertIdempotencyKey(call.idempotencyKey);

  let bodyBytes: Uint8Array | undefined;
  if (call.jsonBody !== undefined) {
    const json = JSON.stringify(call.jsonBody);
    if (typeof json !== "string") {
      throw new TypeError("request body must be JSON-serializable");
    }
    bodyBytes = new TextEncoder().encode(json);
  }
  const rawBody = bodyBytes ?? EMPTY_BODY;

  const timestamp = unixSeconds(transport.now);
  const message = signingBytes(transport.apiKey, timestamp, call.method, call.pathAndQuery, rawBody);
  const signature = assertSignatureHeader(await transport.sign(message));

  const headers = new Headers();
  headers.set(API_KEY_HEADER, transport.apiKey);
  headers.set(TIMESTAMP_HEADER, timestamp);
  headers.set(PAYLOAD_SIGNATURE_HEADER, signature);
  if (bodyBytes !== undefined) headers.set(CONTENT_TYPE_HEADER, JSON_CONTENT_TYPE);
  if (idempotencyKey !== undefined) headers.set(IDEMPOTENCY_KEY_HEADER, idempotencyKey);

  const url = resolveRelayUrl(transport.origin, call.pathAndQuery);
  const init: RequestInit = {
    method: call.method,
    headers,
    redirect: "error",
  };
  if (bodyBytes !== undefined) init.body = bodyBytes;
  if (call.signal !== undefined) init.signal = call.signal;

  const response = await transport.fetch(url, init);
  return readResponse<T>(response, call.successStatuses);
}

async function readResponse<T>(response: Response, successStatuses: readonly number[]): Promise<T> {
  const requestId = readRequestId(response.headers.get(REQUEST_ID_HEADER));
  const retryAfter = readRetryAfter(response.headers.get(RETRY_AFTER_HEADER));
  const text = await response.text();
  const ok = successStatuses.includes(response.status);

  let parsed: unknown;
  if (text.length > 0) {
    try {
      parsed = JSON.parse(text) as unknown;
    } catch {
      throw new RelayError({
        status: response.status,
        message: ok ? invalidJsonMessage() : "Relay request failed",
        ...(requestId !== undefined ? { requestId } : {}),
        ...(retryAfter !== undefined ? { retryAfter } : {}),
      });
    }
  }

  if (ok) {
    if (parsed === undefined) {
      throw new RelayError({
        status: response.status,
        message: invalidJsonMessage(),
        ...(requestId !== undefined ? { requestId } : {}),
      });
    }
    return parsed as T;
  }

  return Promise.reject(toRelayError({ status: response.status, parsed, requestId, retryAfter }));
}
