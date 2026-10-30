/**
 * Signed client and webhook verifier for Relay `/api/v1`.
 *
 * Import from this entry. `paths` and header-name constants stay internal.
 */

export { createRelay, DEFAULT_BASE_URL } from "./client.js";
export type {
  CreateRelayOptions,
  GetEventOptions,
  IdempotentOptions,
  Relay,
  RelayEvents,
  RelayFetch,
  RelayQueues,
  RelaySchedules,
  RequestOptions,
  SignFn,
} from "./client.js";

export { verifyWebhook } from "./webhook.js";
export type { VerifiedWebhook, VerifyWebhookOptions } from "./webhook.js";
export type { WebhookHeaders } from "./read-header.js";

export { RelayError, WebhookVerificationError } from "./errors.js";
export type { WebhookVerificationReason } from "./errors.js";

export type {
  AcceptedEventResponse,
  ApiErrorObject,
  ApiErrorResponse,
  Checkpoint,
  CheckpointInput,
  ClientResultError,
  ClientStatus,
  CodedError,
  CreateQueueRequest,
  CreateQueueResponse,
  CreateScheduleRequest,
  DeletedScheduleResponse,
  DeliveryAttempt,
  DeliveryTiming,
  Event,
  EventQuotaExceededResponse,
  EventResultResponse,
  EventWithAttempts,
  GetEventQuery,
  GetEventResponse,
  IdempotencyConflictResponse,
  JsonObject,
  JsonPrimitive,
  JsonValue,
  PostCheckpointsRequest,
  PostCheckpointsResponse,
  PostEventResultRequest,
  Queue,
  QueueRules,
  RateLimitResponse,
  RelayErrorCode,
  RelayErrorStatus,
  Rfc3339,
  Schedule,
  ScheduleLimitExceededResponse,
  ScheduleListResponse,
  ScheduleResponse,
  SendMessageEvent,
  ServerStatus,
  SubmitEventRequest,
  SubmitSendMessageRequest,
  SubscriptionRequiredResponse,
  ValidationErrorResponse,
  ValidationIssue,
  WebhookAuthMode,
  WebhookDeliveryBody,
} from "relay-types";

export {
  CLIENT_STATUSES,
  DEFAULT_QUEUE_RULES,
  MAX_CHECKPOINT_BATCH,
  MAX_CHECKPOINTS_PER_EVENT,
  MAX_DELAY_SECONDS,
  MAX_DELIVERY_DELAY_DAYS,
  MAX_IDEMPOTENCY_KEY_LENGTH,
  MAX_SCHEDULES_PER_CLIENT,
  SERVER_STATUSES,
  TIMESTAMP_SKEW_SECONDS,
} from "relay-types";
