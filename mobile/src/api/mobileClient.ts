const DEFAULT_API_URL =
  process.env.EXPO_PUBLIC_API_URL || "http://10.0.2.2:4000";

export async function mobileApi<T>(
  path: string,
  token: string | null,
  options: RequestInit = {}
): Promise<T> {
  const headers: Record<string, string> = {
    "Content-Type": "application/json",
    "X-ThreatLens-Client": "expo-android-soc",
    ...(options.headers as Record<string, string> | undefined),
  };

  if (token) {
    headers.Authorization = `Bearer ${token}`;
  }

  const res = await fetch(`${DEFAULT_API_URL}${path}`, {
    ...options,
    headers,
  });
  const body = await res.json().catch(() => ({}));
  if (!res.ok) {
    throw new Error(body?.error || `HTTP ${res.status}`);
  }
  return body as T;
}
