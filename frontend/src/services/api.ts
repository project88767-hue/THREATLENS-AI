const API_BASE = (import.meta.env.VITE_API_BASE_URL as string | undefined) ?? "";

const TOKEN_STORAGE_KEY = "threatlens_access_token";

export function getStoredToken(): string | null {
  return localStorage.getItem(TOKEN_STORAGE_KEY);
}

export function setStoredToken(token: string | null): void {
  if (token) {
    localStorage.setItem(TOKEN_STORAGE_KEY, token);
  } else {
    localStorage.removeItem(TOKEN_STORAGE_KEY);
  }
}

export async function apiRequest<T>(
  path: string,
  options: RequestInit = {}
): Promise<T> {
  const token = getStoredToken();
  const headers: Record<string, string> = {
    "Content-Type": "application/json",
    "X-ThreatLens-Client": "web-soc-console",
    ...(options.headers as Record<string, string> | undefined),
  };

  if (token) {
    headers.Authorization = `Bearer ${token}`;
  }

  const response = await fetch(`${API_BASE}${path}`, {
    ...options,
    credentials: "include",
    headers,
  });

  const data = await response.json().catch(() => ({}));
  if (!response.ok) {
    const detailMsg = Array.isArray(data?.details)
      ? data.details.map((d: { message: string }) => d.message).join("; ")
      : "";
    throw new Error(detailMsg || data?.error || `Request failed (${response.status})`);
  }

  return data as T;
}
