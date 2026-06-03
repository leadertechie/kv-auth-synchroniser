import { HEADERS, SIGNATURE_TTL_MS } from "../constants";
import { Identity } from "../core/identity";
import { 
  MissingHeaderError, 
  SignatureExpiredError, 
  UnknownCallerError,
  SignatureMismatchError,
  VerificationError 
} from "../core/errors";
import { createPayload } from "../core/payload";
import { base64ToBytes } from "../crypto";
import type { VerificationStep, VerificationContext } from "./types";
import type { RegistryEntry } from "../types";

export class HeaderExtractionStep implements VerificationStep {
  readonly name = "extract-headers";

  async execute(ctx: VerificationContext): Promise<VerificationContext> {
    const signature = ctx.request.headers.get(HEADERS.SIGNATURE);
    const caller = ctx.request.headers.get(HEADERS.CALLER);
    const timestampStr = ctx.request.headers.get(HEADERS.TIMESTAMP);
    const userEmail = ctx.request.headers.get(HEADERS.AUTH);

    if (!signature) throw new MissingHeaderError(HEADERS.SIGNATURE);
    if (!caller) throw new MissingHeaderError(HEADERS.CALLER);
    if (!timestampStr) throw new MissingHeaderError(HEADERS.TIMESTAMP);

    const timestamp = parseInt(timestampStr, 10);
    if (isNaN(timestamp)) throw new Error("Invalid timestamp header");

    return {
      ...ctx,
      signature,
      timestamp,
      identity: new Identity(caller, userEmail || ""),
      method: ctx.request.method,
    };
  }
}

export class TimestampValidationStep implements VerificationStep {
  readonly name = "validate-timestamp";

  async execute(ctx: VerificationContext): Promise<VerificationContext> {
    if (!ctx.timestamp) throw new Error("Timestamp not extracted");
    
    if (Date.now() - ctx.timestamp > SIGNATURE_TTL_MS) {
      throw new SignatureExpiredError(ctx.timestamp);
    }
    
    return ctx;
  }
}

export class KeyResolutionStep implements VerificationStep {
  readonly name = "resolve-key";

  async execute(ctx: VerificationContext): Promise<VerificationContext> {
    if (!ctx.identity) throw new Error("Identity not extracted");

    const entry = await ctx.registry.getPublicKey(ctx.identity.caller);
    if (!entry) throw new UnknownCallerError(ctx.identity.caller);

    // Store the full entry for CA verification if needed
    (ctx as any).registryEntry = entry;

    const publicKey = await ctx.algorithm.importPublicKey(base64ToBytes(entry.document.publicKey));
    return { ...ctx, publicKey };
  }
}

export class CATrustStep implements VerificationStep {
  readonly name = "ca-trust-verification";

  constructor(private readonly caPublicKey: CryptoKey) {}

  async execute(ctx: VerificationContext): Promise<VerificationContext> {
    const entry = (ctx as any).registryEntry as RegistryEntry;
    if (!entry) throw new Error("Registry entry not found in context");

    const documentBytes = new TextEncoder().encode(JSON.stringify(entry.document));
    const signatureBytes = base64ToBytes(entry.signature);

    const isTrusted = await crypto.subtle.verify(
      { name: "Ed25519" },
      this.caPublicKey,
      signatureBytes,
      documentBytes
    );

    if (!isTrusted) {
      throw new VerificationError("Identity document not trusted by CA");
    }

    if (Date.now() > entry.document.expiresAt) {
      throw new VerificationError("Identity document has expired");
    }

    return ctx;
  }
}

export class PayloadConstructionStep implements VerificationStep {
  readonly name = "construct-payload";

  async execute(ctx: VerificationContext): Promise<VerificationContext> {
    if (!ctx.identity || !ctx.timestamp || !ctx.method) {
      throw new Error("Missing data for payload construction");
    }

    const url = new URL(ctx.request.url);
    const path = url.pathname + url.search;
    
    let body: string | undefined;
    if (ctx.request.method !== "GET" && ctx.request.method !== "HEAD" && ctx.request.method !== "OPTIONS") {
      try {
        const clone = ctx.request.clone();
        body = await clone.text() || undefined;
      } catch { /* ignore body read errors */ }
    }

    const payload = await createPayload(
      ctx.method,
      path,
      ctx.timestamp,
      ctx.identity.caller,
      ctx.identity.userEmail,
      body
    );

    return { ...ctx, path, body, payload };
  }
}

export class SignatureVerificationStep implements VerificationStep {
  readonly name = "verify-signature";

  async execute(ctx: VerificationContext): Promise<VerificationContext> {
    if (!ctx.publicKey || !ctx.signature || !ctx.payload) {
      throw new Error("Missing data for signature verification");
    }

    const sigBytes = base64ToBytes(ctx.signature);
    const payloadBytes = new TextEncoder().encode(ctx.payload);

    const isValid = await ctx.algorithm.verify(ctx.publicKey, sigBytes, payloadBytes.buffer);
    if (!isValid) throw new SignatureMismatchError();

    return { ...ctx, isValid: true };
  }
}
