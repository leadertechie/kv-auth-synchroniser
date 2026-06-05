import { Ed25519Algorithm } from "./algorithms/ed25519";
import { KVPublicKeyRegistry } from "./registry/kv-registry";
import { CATrustStep, HeaderExtractionStep, TimestampValidationStep, KeyResolutionStep, PayloadConstructionStep, SignatureVerificationStep } from "./verification/steps";
import { VerificationPipeline, type VerificationStep } from "./verification/types";
import { 
  importPrivateKey, 
  getPublicKeyFromPrivate, 
  bytesToBase64, 
  base64ToBytes,
  importPublicKey
} from "./crypto";
import { sign as coreSign } from "./core/signer";
import { ConfigurationError, VerificationError } from "./core/errors";
import { HEADERS } from "./constants";
import { AuthorityClient, type AuthorityConfig } from "./core/authority";
import type { Algorithm } from "./algorithms/types";
import type { PublicKeyRegistry } from "./registry/types";
import type { LoggerInterface } from "@leadertechie/telemetry";
import type { 
  KVAuthConfig, 
  VerifyResult, 
  SignedHeaders, 
  Keypair, 
  RegistryEntry,
  SignedIdentity 
} from "./types";

export * from "./types";
export * from "./constants";
export * from "./core/errors";
export * from "./core/identity";
export * from "./core/authority";
export * from "./algorithms/types";
export * from "./registry/types";

/**
 * KVAuth Facade
 * Provides a clean API over the modular architecture.
 */
export class KVAuth {
  private privateKey: CryptoKey | null = null;
  private registryEntry: RegistryEntry | null = null;
  private caPublicKey: CryptoKey | null = null;

  constructor(
    private readonly config: KVAuthConfig,
    private readonly algorithm: Algorithm = new Ed25519Algorithm(),
    private readonly registry: PublicKeyRegistry = new KVPublicKeyRegistry(config.kv, config.kvPrefix),
    private readonly options: {
      caPublicKeyB64?: string;
      authority?: AuthorityConfig;
      logger?: LoggerInterface;
    } = {}
  ) {}

  async init(): Promise<void> {
    this.options.logger?.info?.("Initializing KVAuth", { 
      service: this.config.serviceName,
      caEnabled: !!this.options.caPublicKeyB64,
      authorityEnabled: !!this.options.authority
    });

    this.privateKey = await this.algorithm.importPrivateKey(
      base64ToBytes(this.config.privateKey)
    );

    if (this.options.caPublicKeyB64) {
      this.caPublicKey = await importPublicKey(this.options.caPublicKeyB64);
    }

    const publicKey = await getPublicKeyFromPrivate(this.privateKey);
    const spki = await (crypto.subtle.exportKey as any)("spki", publicKey);
    const spkiB64 = bytesToBase64(new Uint8Array(spki));

    // If authority is configured, request a signed identity
    if (this.options.authority) {
      this.options.logger?.debug?.("Requesting identity from authority", { 
        url: this.options.authority.baseUrl 
      });
      const client = new AuthorityClient(this.options.authority);
      const signedIdentity = await client.requestIdentity(this.config.serviceName, spkiB64);

      this.registryEntry = {
        ...signedIdentity,
        updated: Date.now(),
      };
      this.options.logger?.info?.("CA-signed identity acquired", { 
        caller: signedIdentity.document.caller,
        expires: new Date(signedIdentity.document.expiresAt).toISOString()
      });
    } else {
      // Legacy/Self-signed (NOT RECOMMENDED for production)
      this.options.logger?.warn?.("Operating in self-signed mode. Not recommended for production.");
      this.registryEntry = {
        document: {
          caller: this.config.serviceName,
          publicKey: spkiB64,
          algorithm: this.algorithm.name,
          issuedAt: Date.now(),
          expiresAt: Date.now() + (365 * 24 * 60 * 60 * 1000), // 1 year
        },
        signature: "", // Self-signed mode has no CA signature
        updated: Date.now(),
      };
    }
  }

  async publishPublicKey(): Promise<void> {
    if (!this.registryEntry) throw new ConfigurationError("Call init() first");
    this.options.logger?.debug?.("Publishing identity to registry", { 
      service: this.config.serviceName 
    });
    await this.registry.publishPublicKey(this.config.serviceName, this.registryEntry);
    this.options.logger?.info?.("Identity published successfully");
  }

  async signRequest(
    method: string,
    path: string,
    options?: { body?: string; userEmail?: string; timestamp?: number },
  ): Promise<SignedHeaders> {
    if (!this.privateKey) throw new ConfigurationError("Call init() first");
    this.options.logger?.debug?.("Signing request", { method, path, user: options?.userEmail });
    return coreSign(this.privateKey, this.config.serviceName, method, path, options);
  }

  async verifyRequest(request: Request): Promise<VerifyResult> {
    const steps: VerificationStep[] = [
      new HeaderExtractionStep(),
      new TimestampValidationStep(),
      new KeyResolutionStep(),
    ];

    // If CA public key is provided, enforce trust verification
    if (this.caPublicKey) {
      steps.push(new CATrustStep(this.caPublicKey));
    }

    steps.push(new PayloadConstructionStep());
    steps.push(new SignatureVerificationStep());

    const pipeline = new VerificationPipeline(steps, this.options.logger);

    try {
      const result = await pipeline.run({
        request,
        algorithm: this.algorithm,
        registry: this.registry,
        logger: this.options.logger,
      });

      this.options.logger?.info?.("Verification successful", {
        caller: result.identity?.caller,
        user: result.identity?.userEmail
      });

      return {
        valid: !!result.isValid,
        caller: result.identity?.caller || null,
        userEmail: result.identity?.userEmail || null,
      };
    } catch (e) {
      if (e instanceof VerificationError) {
        this.options.logger?.warn?.(`Verification failed: ${e.message}`, {
          error: e.name,
          url: request.url
        });
        return {
          valid: false,
          caller: (e as any).caller || null,
          userEmail: null,
        };
      }
      this.options.logger?.error?.("Unexpected error during verification", e instanceof Error ? e : new Error(String(e)));
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
  private caPublicKeyB64?: string;
  private authority?: AuthorityConfig;
  private logger?: LoggerInterface;

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

  withCA(publicKeyB64: string): this {
    this.caPublicKeyB64 = publicKeyB64;
    return this;
  }

  withAuthority(authority: AuthorityConfig): this {
    this.authority = authority;
    return this;
  }

  withLogger(logger: LoggerInterface): this {
    this.logger = logger;
    return this;
  }

  build(): KVAuth {
    if (!this.config) throw new ConfigurationError("Config is required");
    const registry = this.registry || new KVPublicKeyRegistry(this.config.kv, this.config.kvPrefix);
    return new KVAuth(this.config, this.algorithm, registry, {
      caPublicKeyB64: this.caPublicKeyB64,
      authority: this.authority,
      logger: this.logger
    });
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
    userEmail: options?.userEmail,
    timestamp: options?.timestamp
  });
  return {
    signature: headers[HEADERS.SIGNATURE],
    timestamp: parseInt(headers[HEADERS.TIMESTAMP], 10)
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
