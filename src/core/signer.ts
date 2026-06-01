import { createPayload } from "./payload";
import { bytesToBase64 } from "../crypto";
import { HEADERS } from "../constants";
import type { SignedHeaders } from "../types";

export interface SignOptions {
  body?: string;
  userEmail?: string;
  timestamp?: number;
}

export async function sign(
  privateKey: CryptoKey,
  serviceName: string,
  method: string,
  path: string,
  options?: SignOptions
): Promise<SignedHeaders> {
  const timestamp = options?.timestamp ?? Date.now();
  const userEmail = options?.userEmail || "";
  
  const payload = await createPayload(
    method,
    path,
    timestamp,
    serviceName,
    userEmail,
    options?.body
  );

  const sig = await crypto.subtle.sign(
    { name: "Ed25519" },
    privateKey,
    new TextEncoder().encode(payload)
  );

  const headers: SignedHeaders = {
    [HEADERS.SIGNATURE]: bytesToBase64(new Uint8Array(sig)),
    [HEADERS.CALLER]: serviceName,
    [HEADERS.TIMESTAMP]: String(timestamp),
  };

  if (options?.userEmail) {
    headers[HEADERS.AUTH] = options.userEmail;
  }

  return headers;
}
