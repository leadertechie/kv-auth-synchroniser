export const DEFAULT_KV_PREFIX = "pubkeys/";
export const SIGNATURE_TTL_MS = 5 * 60 * 1000;

export const HEADERS = {
  SIGNATURE: "X-Toldby-Signature",
  CALLER: "X-Toldby-Caller",
  TIMESTAMP: "X-Toldby-Timestamp",
  AUTH: "X-Toldby-Auth",
} as const;
