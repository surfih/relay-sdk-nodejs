import {
  createHash,
  createHmac,
  createPrivateKey,
  createPublicKey,
  sign as cryptoSign,
  timingSafeEqual,
  verify as cryptoVerify,
  type KeyObject,
} from "node:crypto";
import { MAX_IDEMPOTENCY_KEY_LENGTH } from "relay-types";

export const SIGNATURE_FORMAT_ERROR =
  "sign() must return sha256=<64 lowercase hex> or ed25519=<standard base64 of 64 bytes>";

const PRIVATE_KEY_ERROR = "privateKeyPem must be a PKCS#8 Ed25519 private key";
const PUBLIC_KEY_ERROR = "deliveryPublicKeyPem must be an SPKI Ed25519 public key";
const ED25519_B64 = /^[A-Za-z0-9+/]{86}==$/;
const HMAC_HEADER = /^sha256=[0-9a-f]{64}$/;

/** Bytes the custom `sign` hook receives: UTF-8 `apiKey.timestamp.METHOD.path.rawBody`. */
export type SignFn = (bytes: Uint8Array) => string | Promise<string>;

export type Signer = (bytes: Uint8Array) => string | Promise<string>;

export function isPrintableAscii(value: string): boolean {
  for (let i = 0; i < value.length; i++) {
    const code = value.charCodeAt(i);
    if (code < 0x20 || code > 0x7e) return false;
  }
  return true;
}

export function assertApiKey(apiKey: string): string {
  if (typeof apiKey !== "string" || apiKey.length === 0) {
    throw new TypeError("apiKey must be a non-empty string");
  }
  if (!isPrintableAscii(apiKey)) {
    throw new TypeError("apiKey must be printable ASCII");
  }
  return apiKey;
}

/**
 * Trim, reject empty, count Unicode code points (max {@link MAX_IDEMPOTENCY_KEY_LENGTH}),
 * and reject CR, LF, NUL, and any other non-printable ASCII.
 */
export function assertIdempotencyKey(key: string): string {
  if (typeof key !== "string") {
    throw new TypeError("idempotencyKey must be a string");
  }
  const trimmed = key.trim();
  if (trimmed.length === 0) {
    throw new TypeError("idempotencyKey must not be empty");
  }
  if ([...trimmed].length > MAX_IDEMPOTENCY_KEY_LENGTH) {
    throw new TypeError("idempotencyKey must be at most 200 characters");
  }
  if (!isPrintableAscii(trimmed)) {
    throw new TypeError("idempotencyKey must be printable ASCII");
  }
  return trimmed;
}

export function assertSecret(secret: string): string {
  if (typeof secret !== "string" || secret.length === 0) {
    throw new TypeError("secret must be a non-empty string");
  }
  return secret;
}

/** Refuse a private-key PEM in `request_public_key_pem` before it is serialized or sent. */
export function assertPublicRequestKey(pem: string | undefined): void {
  if (pem === undefined) return;
  if (typeof pem !== "string" || /PRIVATE\s+KEY/i.test(pem)) {
    throw new TypeError("request_public_key_pem must be a public key");
  }
}

export function rawBodyBytes(body: string | Uint8Array): Uint8Array {
  if (typeof body === "string") return new TextEncoder().encode(body);
  if (body instanceof Uint8Array) return body;
  throw new TypeError("rawBody must be a string or Uint8Array");
}

export function signingBytes(
  apiKey: string,
  timestamp: string,
  method: string,
  pathAndQuery: string,
  rawBody: Uint8Array,
): Uint8Array {
  const prefix = new TextEncoder().encode(
    `${apiKey}.${timestamp}.${method.toUpperCase()}.${pathAndQuery}.`,
  );
  const out = new Uint8Array(prefix.length + rawBody.length);
  out.set(prefix, 0);
  out.set(rawBody, prefix.length);
  return out;
}

export function unixSeconds(now: () => number): string {
  const ms = now();
  if (typeof ms !== "number" || !Number.isFinite(ms)) {
    throw new TypeError("now() must return milliseconds since the Unix epoch");
  }
  const seconds = Math.floor(ms / 1000);
  if (!Number.isSafeInteger(seconds) || seconds < 0) {
    throw new TypeError("now() must return milliseconds since the Unix epoch");
  }
  return String(seconds);
}

/** `sha256=` + lowercase hex. `message` may be a Uint8Array view. */
export function hmacSha256Header(secret: string, message: Uint8Array): string {
  const hex = createHmac("sha256", secret).update(message).digest("hex");
  return `sha256=${hex}`;
}

/** Webhook HMAC over `apiKey + "." + rawBody` as three updates. `rawBody` may be a view. */
export function webhookHmacHeader(secret: string, apiKey: string, rawBody: Uint8Array): string {
  const hex = createHmac("sha256", secret).update(apiKey).update(".").update(rawBody).digest("hex");
  return `sha256=${hex}`;
}

/** Lowercase hex SHA-256. `bytes` may be a Uint8Array view. */
export function sha256Hex(bytes: Uint8Array): string {
  return createHash("sha256").update(bytes).digest("hex");
}

export function timingSafeEqualText(left: string, right: string): boolean {
  const a = Buffer.from(left);
  const b = Buffer.from(right);
  if (a.length !== b.length) return false;
  return timingSafeEqual(a, b);
}

export function loadEd25519PrivateKey(pem: string): KeyObject {
  if (typeof pem !== "string" || !pem.includes("BEGIN PRIVATE KEY") || /ENCRYPTED PRIVATE KEY/.test(pem)) {
    throw new TypeError(PRIVATE_KEY_ERROR);
  }
  let key: KeyObject;
  try {
    key = createPrivateKey(pem);
  } catch {
    throw new TypeError(PRIVATE_KEY_ERROR);
  }
  if (key.type !== "private" || key.asymmetricKeyType !== "ed25519") {
    throw new TypeError(PRIVATE_KEY_ERROR);
  }
  return key;
}

export function loadEd25519PublicKey(pem: string): KeyObject {
  if (typeof pem !== "string" || !pem.includes("BEGIN PUBLIC KEY") || /PRIVATE\s+KEY/i.test(pem)) {
    throw new TypeError(PUBLIC_KEY_ERROR);
  }
  let key: KeyObject;
  try {
    key = createPublicKey(pem);
  } catch {
    throw new TypeError(PUBLIC_KEY_ERROR);
  }
  if (key.type !== "public" || key.asymmetricKeyType !== "ed25519") {
    throw new TypeError(PUBLIC_KEY_ERROR);
  }
  return key;
}

export function signEd25519(key: KeyObject, message: Uint8Array): string {
  const signature = cryptoSign(null, message, key);
  if (signature.length !== 64) {
    throw new TypeError("Ed25519 signature must be 64 bytes");
  }
  return `ed25519=${signature.toString("base64")}`;
}

export function assertSignatureHeader(value: string): string {
  if (typeof value !== "string") {
    throw new TypeError(SIGNATURE_FORMAT_ERROR);
  }
  const trimmed = value.trim();
  if (HMAC_HEADER.test(trimmed)) return trimmed;
  if (trimmed.startsWith("ed25519=") && isCanonicalEd25519Body(trimmed.slice("ed25519=".length))) {
    return trimmed;
  }
  throw new TypeError(SIGNATURE_FORMAT_ERROR);
}

export function verifyEd25519Signature(publicKey: KeyObject, message: Uint8Array, header: string): boolean {
  if (!header.startsWith("ed25519=")) return false;
  const encoded = header.slice("ed25519=".length);
  if (!isCanonicalEd25519Body(encoded)) return false;
  const signature = Buffer.from(encoded, "base64");
  try {
    return cryptoVerify(null, message, publicKey, signature);
  } catch {
    return false;
  }
}

function isCanonicalEd25519Body(encoded: string): boolean {
  if (!ED25519_B64.test(encoded)) return false;
  const decoded = Buffer.from(encoded, "base64");
  return decoded.length === 64 && decoded.toString("base64") === encoded;
}

export function hmacSigner(secret: string): Signer {
  return (bytes) => hmacSha256Header(secret, bytes);
}

export function ed25519Signer(pem: string): Signer {
  const key = loadEd25519PrivateKey(pem);
  return (bytes) => signEd25519(key, bytes);
}

export function customSigner(sign: SignFn): Signer {
  if (typeof sign !== "function") {
    throw new TypeError("sign must be a function");
  }
  return async (bytes) => {
    const value = await sign(bytes);
    return assertSignatureHeader(value);
  };
}
