import { WebhookVerificationError } from "./errors.js";

/** Header bag: Fetch `Headers`, or a Node-style map whose values may be `string[]`. */
export type WebhookHeaders =
  | Headers
  | { readonly [name: string]: string | readonly string[] | undefined };

const MAX_HEADER_VALUE = 4096;

function isHeaders(value: unknown): value is Headers {
  return typeof Headers !== "undefined" && value instanceof Headers;
}

/**
 * Case-insensitive read. Values are trimmed. A `string[]` is accepted only when its length is 1;
 * a longer list fails instead of using the first entry.
 */
export function readWebhookHeader(headers: WebhookHeaders, name: string): string {
  const lower = name.toLowerCase();
  if (isHeaders(headers)) {
    return requireTrimmed(headers.get(lower));
  }
  if (headers === null || typeof headers !== "object") {
    throw new WebhookVerificationError("headers");
  }

  const matches: (string | readonly string[] | undefined)[] = [];
  for (const key of Object.keys(headers)) {
    if (key.toLowerCase() !== lower) continue;
    matches.push(headers[key]);
  }
  if (matches.length !== 1) throw new WebhookVerificationError("headers");
  const found = matches[0];
  if (typeof found === "string") return requireTrimmed(found);
  if (Array.isArray(found)) {
    if (found.length !== 1) throw new WebhookVerificationError("headers");
    const only = found[0];
    if (typeof only !== "string") throw new WebhookVerificationError("headers");
    return requireTrimmed(only);
  }
  throw new WebhookVerificationError("headers");
}

function requireTrimmed(value: string | null | undefined): string {
  if (typeof value !== "string") throw new WebhookVerificationError("headers");
  const trimmed = value.trim();
  if (trimmed.length === 0 || trimmed.length > MAX_HEADER_VALUE) {
    throw new WebhookVerificationError("headers");
  }
  return trimmed;
}
