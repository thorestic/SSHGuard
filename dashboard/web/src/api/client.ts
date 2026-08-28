const API_BASE_URL = import.meta.env.VITE_API_BASE_URL ?? "/api/v1";

export function apiUrl(path: string): string {
  return `${API_BASE_URL.replace(/\/$/, "")}/${path.replace(/^\//, "")}`;
}

export class ApiError extends Error {
  constructor(
    message: string,
    public readonly status: number,
  ) {
    super(message);
    this.name = "ApiError";
  }
}

export async function getJson<T>(
  path: string,
  signal?: AbortSignal,
): Promise<T> {
  const response = await fetch(apiUrl(path), {
    method: "GET",
    headers: { Accept: "application/json" },
    signal,
  });

  if (!response.ok) {
    let message = "The security data service did not respond.";

    try {
      const payload = (await response.json()) as { detail?: string };
      message = payload.detail ?? message;
    } catch {
      // The status code remains available even for a non-JSON proxy error.
    }

    throw new ApiError(message, response.status);
  }

  return (await response.json()) as T;
}

export function toQuery(
  values: Record<string, string | number | undefined>,
): string {
  const query = new URLSearchParams();

  for (const [key, value] of Object.entries(values)) {
    if (value !== undefined && value !== "") {
      query.set(key, String(value));
    }
  }

  const serialized = query.toString();
  return serialized ? `?${serialized}` : "";
}

