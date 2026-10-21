import { createServer, type IncomingMessage, type ServerResponse } from "node:http";
import type { AddressInfo } from "node:net";
import { afterEach } from "vitest";
import type { ScanContext } from "../src/types.js";

type Handler = (req: IncomingMessage, res: ServerResponse) => void;

const open: (() => Promise<void>)[] = [];

afterEach(async () => {
  await Promise.all(open.splice(0).map((close) => close()));
});

/** Starts a throwaway HTTP server on 127.0.0.1 and returns its base URL. Closed after each test. */
export async function serve(handler: Handler): Promise<string> {
  const server = createServer(handler);
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  open.push(
    () =>
      new Promise<void>((resolve) => {
        server.closeAllConnections();
        server.close(() => resolve());
      })
  );
  const { port } = server.address() as AddressInfo;
  return `http://127.0.0.1:${port}`;
}

export function context(url: string, overrides: Partial<ScanContext> = {}): ScanContext {
  const targetUrl = new URL(url);
  return {
    targetUrl,
    timeoutMs: 1000,
    retries: 0,
    retryDelayMs: 1,
    maxRedirects: 5,
    scope: [targetUrl.hostname],
    probeDelayMs: 0,
    ...overrides,
  };
}

/** Headers a well-configured site would send. */
export const SECURE_HEADERS: Record<string, string> = {
  "content-security-policy": "default-src 'self'; frame-ancestors 'none'",
  "x-content-type-options": "nosniff",
  "referrer-policy": "strict-origin-when-cross-origin",
  "permissions-policy": "camera=(), microphone=()",
};
