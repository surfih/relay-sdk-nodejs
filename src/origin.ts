const LOCAL_HOSTS: ReadonlySet<string> = new Set(["localhost", "127.0.0.1", "::1", "[::1]"]);

/**
 * Accept `https` origins. `http` is limited to loopback (`localhost`, `127.0.0.1`, `::1`)
 * unless `allowInsecureHttp` is set. Userinfo, query, hash, and a non-root path are rejected.
 * Returns `url.origin`.
 */
export function assertRelayOrigin(baseUrl: string, allowInsecureHttp: boolean): string {
  if (typeof baseUrl !== "string" || baseUrl.length === 0) {
    throw new TypeError("baseUrl must be an absolute http(s) URL");
  }
  let url: URL;
  try {
    url = new URL(baseUrl);
  } catch {
    throw new TypeError("baseUrl must be an absolute http(s) URL");
  }
  if (url.username !== "" || url.password !== "") {
    throw new TypeError("baseUrl must not include credentials");
  }
  if (url.search !== "" || url.hash !== "") {
    throw new TypeError("baseUrl must not include a query or hash");
  }
  if (url.pathname !== "" && url.pathname !== "/") {
    throw new TypeError("baseUrl must not include a path");
  }
  if (url.protocol === "https:") return url.origin;
  if (url.protocol === "http:" && (allowInsecureHttp || LOCAL_HOSTS.has(url.hostname))) {
    return url.origin;
  }
  throw new TypeError("baseUrl must use https");
}

/**
 * Resolve `pathAndQuery` against `origin`. The result must stay on that origin and its
 * `pathname + search` must equal `pathAndQuery` (no dot-segment or scheme rewrite).
 */
export function resolveRelayUrl(origin: string, pathAndQuery: string): URL {
  if (typeof pathAndQuery !== "string" || !pathAndQuery.startsWith("/")) {
    throw new TypeError("request path escaped the relay origin");
  }
  let url: URL;
  try {
    url = new URL(pathAndQuery, origin);
  } catch {
    throw new TypeError("request path escaped the relay origin");
  }
  if (url.origin !== origin || `${url.pathname}${url.search}` !== pathAndQuery) {
    throw new TypeError("request path escaped the relay origin");
  }
  return url;
}
