import type { Keypair } from "../types";

export interface Algorithm {
  readonly name: string;
  sign(key: CryptoKey, data: ArrayBuffer): Promise<ArrayBuffer>;
  verify(key: CryptoKey, signature: ArrayBuffer, data: ArrayBuffer): Promise<boolean>;
  importPrivateKey(bytes: ArrayBuffer): Promise<CryptoKey>;
  importPublicKey(bytes: ArrayBuffer): Promise<CryptoKey>;
  generateKeypair(): Promise<Keypair>;
}
