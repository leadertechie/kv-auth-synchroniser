import { createPayload } from "./payload";
import { base64ToBytes, sha256 } from "../crypto";

export async function verify(
  publicKey: CryptoKey,
  method: string,
  path: string,
  timestamp: number,
  caller: string,
  userEmail: string,
  signature: string,
  body?: string
): Promise<boolean> {
  const payload = await createPayload(
    method,
    path,
    timestamp,
    caller,
    userEmail,
    body
  );

  const sigBytes = base64ToBytes(signature);
  return crypto.subtle.verify(
    { name: "Ed25519" },
    publicKey,
    sigBytes,
    new TextEncoder().encode(payload)
  );
}
