import { sha256 } from "../crypto";

export async function createPayload(
  method: string,
  path: string,
  timestamp: number,
  caller: string,
  userEmail: string,
  body?: string
): Promise<string> {
  const bodyHash = body ? await sha256(body) : "";
  return `${method}:${path}:${timestamp}:${caller}:${userEmail}:${bodyHash}`;
}
