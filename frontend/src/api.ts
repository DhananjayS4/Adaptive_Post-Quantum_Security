import type { Job, JsonObject, SystemStatus } from "./types";

class ApiError extends Error {
  constructor(
    message: string,
    readonly status: number,
  ) {
    super(message);
  }
}

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  const response = await fetch(`/api/v1${path}`, {
    ...init,
    headers: { "Content-Type": "application/json", ...init?.headers },
  });
  if (!response.ok) {
    const payload = await response.json().catch(() => ({}));
    throw new ApiError(payload.detail ?? `Request failed (${response.status})`, response.status);
  }
  return response.json() as Promise<T>;
}

export const api = {
  status: () => request<SystemStatus>("/status"),
  results: () => request<Record<string, JsonObject>>("/results"),
  evaluatePolicy: (body: JsonObject) =>
    request<JsonObject>("/policy/evaluate", {
      method: "POST",
      body: JSON.stringify(body),
    }),
  secureRoundTrip: (body: JsonObject) =>
    request<JsonObject>("/security/round-trip", {
      method: "POST",
      body: JSON.stringify(body),
    }),
  jobs: () => request<Job[]>("/jobs"),
  submitJob: (kind: string, options: JsonObject) =>
    request<Job>("/jobs", {
      method: "POST",
      body: JSON.stringify({ kind, options }),
    }),
};
