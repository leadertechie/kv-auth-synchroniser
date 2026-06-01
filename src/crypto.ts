import type { Keypair } from "./types";

export async function sha256(data: string): Promise<string> {
  const hash = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(data));
  return bytesToBase64(new Uint8Array(hash));
}

export function bytesToBase64(bytes: Uint8Array): string {
  return btoa(String.fromCharCode(...bytes));
}

export function base64ToBytes(base64: string): ArrayBuffer {
  const binary = atob(base64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
  return bytes.buffer;
}

export async function importPrivateKey(pkcs8B64: string): Promise<CryptoKey> {
  const bytes = base64ToBytes(pkcs8B64);
  return crypto.subtle.importKey(
    "pkcs8", bytes, { name: "Ed25519" }, true, ["sign"],
  );
}

export async function importPublicKey(spkiB64: string): Promise<CryptoKey> {
  const bytes = base64ToBytes(spkiB64);
  return crypto.subtle.importKey(
    "spki", bytes, { name: "Ed25519" }, false, ["verify"],
  );
}

export async function generateKeypair(): Promise<Keypair> {
  const kp = await crypto.subtle.generateKey(
    { name: "Ed25519" }, true, ["sign", "verify"],
  ) as CryptoKeyPair;

  return {
    privateKey: bytesToBase64(new Uint8Array(await (crypto.subtle.exportKey as any)("pkcs8", kp.privateKey))),
    publicKey: {
      raw: bytesToBase64(new Uint8Array(await (crypto.subtle.exportKey as any)("raw", kp.publicKey))),
      spki: bytesToBase64(new Uint8Array(await (crypto.subtle.exportKey as any)("spki", kp.publicKey))),
    },
  };
}

/** Internal helper to get public key from private key */
export async function getPublicKeyFromPrivate(privateKey: CryptoKey): Promise<CryptoKey> {
  const jwk = await crypto.subtle.exportKey("jwk", privateKey) as any;
  const pubJwk: any = {
    kty: "OKP", crv: "Ed25519", x: jwk.x,
    key_ops: ["verify"], ext: true,
  };
  return crypto.subtle.importKey(
    "jwk", pubJwk, { name: "Ed25519" }, true, ["verify"],
  );
}
