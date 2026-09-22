/**
 * Typed API client. Types come from the backend's OpenAPI schema (`npm run gen:api`), so a
 * backend change that breaks the frontend fails `tsc` instead of failing at runtime.
 *
 * The session lives in an HttpOnly cookie the browser sends automatically (same origin). The
 * CSRF token is kept in memory only (never localStorage) and added to every write.
 */
import createClient, { type Middleware } from "openapi-fetch";

import type { components, paths } from "./schema";

export type Schemas = components["schemas"];

let csrfToken: string | null = null;

export function setCsrfToken(token: string | null): void {
  csrfToken = token;
}

const SAFE = new Set(["GET", "HEAD", "OPTIONS"]);

const csrf: Middleware = {
  onRequest({ request }) {
    if (!SAFE.has(request.method) && csrfToken) {
      request.headers.set("X-CSRF-Token", csrfToken);
    }
    return request;
  },
};

// Same origin as the page. An absolute base (not "") keeps Request() happy outside browsers too.
const origin = typeof window === "undefined" ? "http://localhost" : window.location.origin;

export const client = createClient<paths>({
  baseUrl: origin,
  credentials: "same-origin",
  // Look fetch up per request (not once at import), so tests and polyfills can replace it.
  fetch: (request) => globalThis.fetch(request),
});
client.use(csrf);

export interface ErrorBody {
  error: { code: string; message: string; details?: unknown };
}

/** An API failure, carrying the backend's error envelope. */
export class ApiError extends Error {
  constructor(
    readonly status: number,
    readonly code: string,
    message: string,
    readonly details?: unknown,
  ) {
    super(message);
    this.name = "ApiError";
  }
}

function toError(status: number, body: unknown): ApiError {
  const envelope = body as Partial<ErrorBody> | undefined;
  if (envelope?.error) {
    return new ApiError(
      status,
      envelope.error.code,
      envelope.error.message,
      envelope.error.details,
    );
  }
  return new ApiError(
    status,
    "network",
    status ? `Request failed (${status})` : "Can't reach the server.",
  );
}

/** Unwrap an openapi-fetch result: return the data or throw an ApiError. */
export async function unwrap<T>(
  promise: Promise<{ data?: T; error?: unknown; response: Response }>,
): Promise<T> {
  let result: { data?: T; error?: unknown; response: Response };
  try {
    result = await promise;
  } catch {
    throw toError(0, undefined);
  }
  if (result.error !== undefined || !result.response.ok) {
    throw toError(result.response.status, result.error);
  }
  return result.data as T;
}
