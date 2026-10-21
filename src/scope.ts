/**
 * Scope restriction: the scanner only ever sends requests to hosts that match
 * one of these patterns. A pattern is an exact hostname ("example.com") or a
 * subdomain wildcard ("*.example.com", which matches "a.example.com" and
 * "a.b.example.com" but not "example.com" itself).
 */
export function parseScope(raw: string | undefined, target: URL): string[] {
  const patterns = (raw ?? "")
    .split(",")
    .map((s) => s.trim().toLowerCase())
    .filter(Boolean);
  return patterns.length > 0 ? patterns : [target.hostname.toLowerCase()];
}

export function inScope(url: URL, scope: string[]): boolean {
  const host = url.hostname.toLowerCase();
  return scope.some((pattern) => {
    if (pattern.startsWith("*.")) return host.endsWith(pattern.slice(1));
    return host === pattern;
  });
}
