export async function fetchSafe(
  url: string,
  init: RequestInit = {},
  timeoutMs = 8000
): Promise<Response | null> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    return await fetch(url, {
      ...init,
      redirect: "manual",
      signal: controller.signal,
      headers: {
        "User-Agent": "websec-scanner/1.0 (authorized-security-scan)",
        ...(init.headers ?? {}),
      },
    });
  } catch {
    return null;
  } finally {
    clearTimeout(timer);
  }
}
