import { Ed25519Algorithm } from "./algorithms/ed25519";
import { KVPublicKeyRegistry } from "./registry/kv-registry";
import { 
  HeaderExtractionStep, 
  TimestampValidationStep, 
  KeyResolutionStep, 
  PayloadConstructionStep, 
  SignatureVerificationStep 
} from "./verification/steps";
import { VerificationPipeline } from "./verification/types";
import { 
  importPrivateKey, 
  getPublicKeyFromPrivate, 
  bytesToBase64, 
  base64ToBytes 
} from "./crypto";
import { sign as coreSign } from "./core/signer";
import { ConfigurationError, VerificationError } from "./core/errors";
import { HEADERS } from "./constants";
import type { Algorithm } from "./algorithms/types";
import type { PublicKeyRegistry } from "./registry/types";
import type { 
  KVAuthConfig, 
  VerifyResult, 
  SignedHeaders, 
  Keypair, 
  RegistryEntry 
} from "./types";

export * from "./types";
export * from "./constants";
export * from "./core/errors";
export * from "./core/identity";
export * from "./algorithms/types";
export * from "./registry/types";

/**
 * KVAuth Facade
 * Provides a clean API over the modular architecture.
 */
export class KVAuth {
  private privateKey: CryptoKey | null = null;
  private registryEntry: RegistryEntry | null = null;

  constructor(
    private readonly config: KVAuthConfig,
    private readonly algorithm: Algorithm = new Ed25519Algorithm(),
    private readonly registry: PublicKeyRegistry = new KVPublicKeyRegistry(config.kv, config.kvPrefix)
  ) {}

  async init(): Promise<void> {
    this.privateKey = await this.algorithm.importPrivateKey(
      base64ToBytes(this.config.privateKey)
    );
    
    const publicKey = await getPublicKeyFromPrivate(this.privateKey);
    
    const raw = await (crypto.subtle.exportKey as any)("raw", publicKey);
    const spki = await (crypto.subtle.exportKey as any)("spki", publicKey);

    this.registryEntry = {
      raw: bytesToBase64(new Uint8Array(raw)),
      spki: bytesToBase64(new Uint8Array(spki)),
      algorithm: this.algorithm.name,
      updated: Date.now(),
    };
  }

  async publishPublicKey(): Promise<void> {
    if (!this.registryEntry) throw new ConfigurationError("Call init() first");
    await this.registry.publishPublicKey(this.config.serviceName, this.registryEntry);
  }

  async signRequest(
    method: string,
    path: string,
    options?: { body?: string; userEmail?: string },
  ): Promise<SignedHeaders> {
    if (!this.privateKey) throw new ConfigurationError("Call init() first");
    return coreSign(this.privateKey, this.config.serviceName, method, path, options);
  }

  async verifyRequest(request: Request): Promise<VerifyResult> {
    const pipeline = new VerificationPipeline([
      new HeaderExtractionStep(),
      new TimestampValidationStep(),
      new KeyResolutionStep(),
      new PayloadConstructionStep(),
      new SignatureVerificationStep(),
    ]);

    try {
      const result = await pipeline.run({
        request,
        algorithm: this.algorithm,
        registry: this.registry,
      });

      return {
        valid: !!result.isValid,
        caller: result.identity?.caller || null,
        userEmail: result.identity?.userEmail || null,
      };
    } catch (e) {
      if (e instanceof VerificationError) {
        return {
          valid: false,
          caller: (e as any).caller || null, // Best effort
          userEmail: null,
        };
      }
      throw e;
    }
  }

  static async generateKeypair(): Promise<Keypair> {
    return new Ed25519Algorithm().generateKeypair();
  }
}

/**
 * KVAuthBuilder - Fluent interface for configuration
 */
export class KVAuthBuilder {
  private config?: KVAuthConfig;
  private algorithm: Algorithm = new Ed25519Algorithm();
  private registry?: PublicKeyRegistry;

  withConfig(config: KVAuthConfig): this {
    this.config = config;
    return this;
  }

  withAlgorithm(algo: Algorithm): this {
    this.algorithm = algo;
    return this;
  }

  withRegistry(registry: PublicKeyRegistry): this {
    this.registry = registry;
    return this;
  }

  build(): KVAuth {
    if (!this.config) throw new ConfigurationError("Config is required");
    const registry = this.registry || new KVPublicKeyRegistry(this.config.kv, this.config.kvPrefix);
    return new KVAuth(this.config, this.algorithm, registry);
  }
}

// ─── Legacy Functional API (Wrappers) ────────────────────────────────

export async function generateKeypair(): Promise<Keypair> {
  return KVAuth.generateKeypair();
}

export async function signRequest(
  privateKeyB64: string, method: string, path: string,
  options?: { body?: string; timestamp?: number; caller?: string; userEmail?: string },
): Promise<{ signature: string; timestamp: number }> {
  const auth = new KVAuth({
    privateKey: privateKeyB64,
    serviceName: options?.caller || "unknown",
    kv: null
  });
  await auth.init();
  const headers = await auth.signRequest(method, path, {
    body: options?.body,
    userEmail: options?.userEmail
  });
  return {
    signature: headers[HEADERS.SIGNATURE],
    timestamp: options?.timestamp ?? Date.now()
  };
}

export async function verifyIncomingRequest(
  request: Request, kv: any,
  kvPrefix?: string,
): Promise<VerifyResult> {
  const auth = new KVAuth({
    privateKey: "", // Not needed for verification
    serviceName: "",
    kv,
    kvPrefix
  });
  return auth.verifyRequest(request);
}
