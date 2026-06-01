import type { Algorithm } from "./types";
import type { Keypair } from "../types";
import { bytesToBase64, base64ToBytes } from "../crypto";

export class Ed25519Algorithm implements Algorithm {
  readonly name = "Ed25519";

  async sign(key: CryptoKey, data: ArrayBuffer): Promise<ArrayBuffer> {
    return crypto.subtle.sign({ name: "Ed25519" }, key, data);
  }

  async verify(key: CryptoKey, signature: ArrayBuffer, data: ArrayBuffer): Promise<boolean> {
    return crypto.subtle.verify({ name: "Ed25519" }, key, signature, data);
  }

  async importPrivateKey(bytes: ArrayBuffer): Promise<CryptoKey> {
    return crypto.subtle.importKey(
      "pkcs8", bytes, { name: "Ed25519" }, true, ["sign"],
    );
  }

  async importPublicKey(bytes: ArrayBuffer): Promise<CryptoKey> {
    return crypto.subtle.importKey(
      "spki", bytes, { name: "Ed25519" }, false, ["verify"],
    );
  }

  async generateKeypair(): Promise<Keypair> {
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
}
