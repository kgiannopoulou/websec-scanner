import { describe, expect, it } from "vitest";
import { fetchChain, fetchSafe, OutOfScopeError } from "../src/http.js";
import { inScope, parseScope } from "../src/scope.js";
import { context, serve } from "./helpers.js";

describe("scope", () => {
  it("defaults to the target host only", () => {
    expect(parseScope(undefined, new URL("https://app.example.com/x"))).toEqual(["app.example.com"]);
  });

  it("matches exact hosts and subdomain wildcards", () => {
    const scope = parseScope("example.com, *.example.com", new URL("https://example.com"));
    expect(inScope(new URL("https://example.com"), scope)).toBe(true);
    expect(inScope(new URL("https://a.b.example.com"), scope)).toBe(true);
    expect(inScope(new URL("https://example.com.evil.net"), scope)).toBe(false);
    expect(inScope(new URL("https://notexample.com"), scope)).toBe(false);
  });

  it("wildcard does not match the apex domain", () => {
    expect(inScope(new URL("https://example.com"), ["*.example.com"])).toBe(false);
  });
});

describe("fetchChain", () => {
  it("refuses to request an out-of-scope URL", async () => {
    const ctx = context("http://127.0.0.1:1", { scope: ["example.com"] });
    await expect(fetchChain(ctx, "http://127.0.0.1:1/")).rejects.toBeInstanceOf(OutOfScopeError);
  });

  it("follows in-scope redirects and returns every hop", async () => {
    const base = await serve((req, res) => {
      if (req.url === "/") res.writeHead(302, { location: "/login" }).end();
      else res.writeHead(200).end("ok");
    });
    const chain = await fetchChain(context(base), `${base}/`);
    expect(chain.map((r) => r.status)).toEqual([302, 200]);
    expect(chain[1].url).toBe(`${base}/login`);
  });

  it("stops at a redirect that leaves the scope", async () => {
    const base = await serve((_req, res) => res.writeHead(301, { location: "https://evil.example.net/" }).end());
    const chain = await fetchChain(context(base), `${base}/`);
    expect(chain).toHaveLength(1);
    expect(chain[0].status).toBe(301);
  });

  it("does not follow non-http(s) redirect targets", async () => {
    const base = await serve((_req, res) => res.writeHead(302, { location: "file:///etc/passwd" }).end());
    const chain = await fetchChain(context(base), `${base}/`);
    expect(chain).toHaveLength(1);
  });

  it("caps the number of redirects", async () => {
    let hits = 0;
    const base = await serve((_req, res) => {
      hits++;
      res.writeHead(302, { location: `/loop${hits}` }).end();
    });
    const chain = await fetchChain(context(base, { maxRedirects: 3 }), `${base}/`);
    expect(chain).toHaveLength(4); // the first request plus three hops
    expect(hits).toBe(4);
  });

  it("retries a 503 and returns the successful response", async () => {
    let hits = 0;
    const base = await serve((_req, res) => {
      hits++;
      if (hits === 1) res.writeHead(503).end();
      else res.writeHead(200).end("ok");
    });
    const res = await fetchSafe(context(base, { retries: 2 }), `${base}/`);
    expect(res?.status).toBe(200);
    expect(hits).toBe(2);
  });

  it("returns the last 503 once retries are exhausted", async () => {
    let hits = 0;
    const base = await serve((_req, res) => {
      hits++;
      res.writeHead(503).end();
    });
    const res = await fetchSafe(context(base, { retries: 1 }), `${base}/`);
    expect(res?.status).toBe(503);
    expect(hits).toBe(2);
  });

  it("returns null when the request times out", async () => {
    const base = await serve(() => {
      /* never respond */
    });
    const res = await fetchSafe(context(base, { timeoutMs: 100 }), `${base}/`);
    expect(res).toBeNull();
  });
});
