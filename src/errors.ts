import type { RelayErrorCode, ValidationIssue } from "relay-types";
import { isPrintableAscii } from "./sign.js";

/** Server `error.message` is kept up to this many Unicode code points. */
export const MAX_ERROR_MESSAGE_CODE_POINTS = 500;

const FALLBACK_MESSAGE = "Relay request failed";
const INVALID_JSON_MESSAGE = "Relay response was not valid JSON";

export function capCodePoints(value: string, max: number): string {
  const points = [...value];
  if (points.length <= max) return value;
  return points.slice(0, max).join("");
}

export interface RelayErrorInit {
  status: number;
  message: string;
  code?: string;
  requestId?: string;
  retryAfter?: number;
  existingEventId?: string;
  issues?: readonly ValidationIssue[];
  eventAllowance?: number;
  eventsUsed?: number;
  scheduleLimit?: number;
  expiresAt?: string | null;
}

/**
 * Failure from `/api/v1`. `message` is the server `error.message`, capped, and never includes
 * request credentials. `existingEventId` is set from a 409 `existing_event_id`. `retryAfter`
 * is the `Retry-After` delta-seconds, when the header is a non-negative integer.
 */
export class RelayError extends Error {
  override readonly name = "RelayError";
  readonly status: number;
  readonly code?: string;
  readonly requestId?: string;
  readonly retryAfter?: number;
  readonly existingEventId?: string;
  readonly issues?: readonly ValidationIssue[];
  readonly eventAllowance?: number;
  readonly eventsUsed?: number;
  readonly scheduleLimit?: number;
  readonly expiresAt?: string | null;

  constructor(init: RelayErrorInit) {
    super(init.message);
    Object.setPrototypeOf(this, new.target.prototype);
    this.status = init.status;
    if (init.code !== undefined) this.code = init.code;
    if (init.requestId !== undefined) this.requestId = init.requestId;
    if (init.retryAfter !== undefined) this.retryAfter = init.retryAfter;
    if (init.existingEventId !== undefined) this.existingEventId = init.existingEventId;
    if (init.issues !== undefined) this.issues = init.issues;
    if (init.eventAllowance !== undefined) this.eventAllowance = init.eventAllowance;
    if (init.eventsUsed !== undefined) this.eventsUsed = init.eventsUsed;
    if (init.scheduleLimit !== undefined) this.scheduleLimit = init.scheduleLimit;
    if (init.expiresAt !== undefined) this.expiresAt = init.expiresAt;
  }
}

export const WEBHOOK_REASONS = ["headers", "signature", "timestamp", "delivery", "body", "mismatch"] as const;

export type WebhookVerificationReason = (typeof WEBHOOK_REASONS)[number];

const WEBHOOK_MESSAGES: Record<WebhookVerificationReason, string> = {
  headers: "webhook headers are missing or invalid",
  signature: "webhook signature verification failed",
  timestamp: "webhook timestamp is invalid",
  delivery: "webhook delivery signature verification failed",
  body: "webhook body is invalid",
  mismatch: "webhook payload does not match signed headers",
};

/** Verification failure. `message` is fixed for `reason` and does not include key material. */
export class WebhookVerificationError extends Error {
  override readonly name = "WebhookVerificationError";
  readonly reason: WebhookVerificationReason;

  constructor(reason: WebhookVerificationReason) {
    super(WEBHOOK_MESSAGES[reason]);
    Object.setPrototypeOf(this, new.target.prototype);
    this.reason = reason;
  }
}

export function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

export function invalidJsonMessage(): string {
  return INVALID_JSON_MESSAGE;
}

export function fallbackErrorMessage(): string {
  return FALLBACK_MESSAGE;
}

export function serverMessage(value: unknown): string {
  if (typeof value !== "string" || value.length === 0) return FALLBACK_MESSAGE;
  return capCodePoints(value, MAX_ERROR_MESSAGE_CODE_POINTS);
}

export function toRelayError(input: {
  status: number;
  parsed: unknown;
  requestId: string | undefined;
  retryAfter: number | undefined;
}): RelayError {
  const init: RelayErrorInit = {
    status: input.status,
    message: FALLBACK_MESSAGE,
  };
  if (input.requestId !== undefined) init.requestId = input.requestId;
  if (input.retryAfter !== undefined) init.retryAfter = input.retryAfter;

  if (!isRecord(input.parsed) || !isRecord(input.parsed.error)) {
    return new RelayError(init);
  }

  const error = input.parsed.error;
  init.message = serverMessage(error.message);

  if (typeof error.code === "string" && isPrintableAscii(error.code) && error.code.length > 0 && error.code.length <= 64) {
    init.code = error.code satisfies RelayErrorCode | string;
  }

  if (typeof error.existing_event_id === "string" && error.existing_event_id.length > 0) {
    init.existingEventId = capCodePoints(error.existing_event_id, 200);
  }

  const issues = readIssues(error.issues);
  if (issues !== undefined) init.issues = issues;

  const eventAllowance = readCount(error.event_allowance);
  if (eventAllowance !== undefined) init.eventAllowance = eventAllowance;
  const eventsUsed = readCount(error.events_used);
  if (eventsUsed !== undefined) init.eventsUsed = eventsUsed;
  const scheduleLimit = readCount(error.schedule_limit);
  if (scheduleLimit !== undefined) init.scheduleLimit = scheduleLimit;

  if (error.expires_at === null) {
    init.expiresAt = null;
  } else if (typeof error.expires_at === "string" && isPrintableAscii(error.expires_at) && error.expires_at.length <= 64) {
    init.expiresAt = error.expires_at;
  }

  return new RelayError(init);
}

function readCount(value: unknown): number | undefined {
  if (typeof value !== "number" || !Number.isSafeInteger(value)) return undefined;
  return value;
}

function readIssues(value: unknown): ValidationIssue[] | undefined {
  if (!Array.isArray(value)) return undefined;
  const issues: ValidationIssue[] = [];
  for (const item of value) {
    if (!isRecord(item) || typeof item.message !== "string" || !Array.isArray(item.path)) continue;
    const path: string[] = [];
    let valid = true;
    for (const part of item.path) {
      if (typeof part !== "string") {
        valid = false;
        break;
      }
      path.push(capCodePoints(part, 200));
    }
    if (!valid) continue;
    issues.push({ path, message: capCodePoints(item.message, MAX_ERROR_MESSAGE_CODE_POINTS) });
    if (issues.length === 20) break;
  }
  return issues.length > 0 ? issues : undefined;
}

export function readRequestId(header: string | null): string | undefined {
  if (header === null) return undefined;
  const trimmed = header.trim();
  if (trimmed.length === 0 || !isPrintableAscii(trimmed)) return undefined;
  return capCodePoints(trimmed, 200);
}

/** `Retry-After` delta-seconds. HTTP-date values are ignored. */
export function readRetryAfter(header: string | null): number | undefined {
  if (header === null) return undefined;
  const trimmed = header.trim();
  if (!/^[0-9]+$/.test(trimmed)) return undefined;
  const value = Number(trimmed);
  if (!Number.isSafeInteger(value)) return undefined;
  return value;
}
