import { inScope } from "./scope.js";
import type { ScanContext } from "./types.js";

export const USER_AGENT = "websec-scanner/1.1 (authorized-security-scan)";

const RETRYABLE_STATUS = new Set([429, 502, 503, 504]);
const REDIRECT_STATUS = new Set([301, 302, 303, 307, 308]);

export class OutOfScopeError extends Error {
  constructor(public readonly url: string) {
    super(`Refusing to request out-of-scope URL: ${url}`);
  }
}

type HttpOptions = Pick<ScanContext, "timeoutMs" | "retries" | "retryDelayMs" | "maxRedirects" | "scope">;

const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

/** One request with a timeout and retries. Never follows redirects itself. */
async function fetchOnce(url: string, init: RequestInit, opts: HttpOptions): Promise<Response | null> {
  for (let attempt = 0; attempt <= opts.retries; attempt++) {
    if (attempt > 0) await sleep(opts.retryDelayMs * 2 ** (attempt - 1));
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), opts.timeoutMs);
    try {
      const res = await fetch(url, {
        ...init,
        redirect: "manual",
        signal: controller.signal,
        headers: { "User-Agent": USER_AGENT, ...(init.headers ?? {}) },
      });
      if (RETRYABLE_STATUS.has(res.status) && attempt < opts.retries) {
        await res.body?.cancel().catch(() => undefined);
        continue;
      }
      return res;
    } catch {
      // Network error or timeout: fall through to the next attempt.
    } finally {
      clearTimeout(timer);
    }
  }
  return null;
}

/**
 * Fetches a URL and follows redirects safely: only http(s), at most
 * `maxRedirects` hops, and never to a host outside the scan scope. Returns
 * every response in the chain (the last one is the final page), or an empty
 * array if the first request failed.
 */
export async function fetchChain(ctx: HttpOptions, url: string, init: RequestInit = {}): Promise<Response[]> {
  let current = new URL(url);
  if (!inScope(current, ctx.scope)) throw new OutOfScopeError(current.toString());

  const chain: Response[] = [];
  for (let hop = 0; hop <= ctx.maxRedirects; hop++) {
    const res = await fetchOnce(current.toString(), init, ctx);
    if (!res) break;
    chain.push(res);

    const location = res.headers.get("location");
    if (!REDIRECT_STATUS.has(res.status) || !location) break;

    let next: URL;
    try {
      next = new URL(location, current);
    } catch {
      break;
    }
    if (next.protocol !== "http:" && next.protocol !== "https:") break;
    if (!inScope(next, ctx.scope)) break; // stop at the boundary, keep the redirect as the final response
    current = next;
  }
  return chain;
}

/** Final response after safe redirect handling, or null if unreachable. */
export async function fetchSafe(ctx: HttpOptions, url: string, init: RequestInit = {}): Promise<Response | null> {
  const chain = await fetchChain(ctx, url, init);
  return chain.at(-1) ?? null;
}
