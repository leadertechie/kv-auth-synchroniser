// @ts-ignore - KVNamespace type from @cloudflare/workers-types
export interface KVAuthConfig {
  /** The service's Ed25519 private key (PKCS8 base64-encoded) */
  privateKey: string;
  /** This service's name — used as the identity in X-Toldby-Caller */
  serviceName: string;
  /** KV namespace binding where public keys are stored */
  kv: any;
  /** Optional prefix for KV keys (default: "pubkeys/") */
  kvPrefix?: string;
}

export interface VerifyResult {
  /** Whether the signature is valid */
  valid: boolean;
  /** The caller's service name (from X-Toldby-Caller) */
  caller: string | null;
  /** The authenticated user email (from X-Toldby-Auth) */
  userEmail: string | null;
}

export interface SignedHeaders {
  "X-Toldby-Signature": string;
  "X-Toldby-Caller": string;
  "X-Toldby-Timestamp": string;
  "X-Toldby-Auth"?: string;
}

export interface Keypair {
  privateKey: string;
  publicKey: {
    raw: string;
    spki: string;
  };
}

export interface IdentityDocument {
  caller: string;
  publicKey: string; // SPKI base64
  algorithm: string;
  issuedAt: number;
  expiresAt: number;
}

export interface SignedIdentity {
  document: IdentityDocument;
  signature: string; // Signature from the CA
}

export interface RegistryEntry extends SignedIdentity {
  updated: number;
}
