import type { Identity } from "../core/identity";
import type { Algorithm } from "../algorithms/types";
import type { PublicKeyRegistry } from "../registry/types";

export interface VerificationContext {
  readonly request: Request;
  readonly algorithm: Algorithm;
  readonly registry: PublicKeyRegistry;
  
  // State populated by steps
  method?: string;
  path?: string;
  timestamp?: number;
  signature?: string;
  identity?: Identity;
  publicKey?: CryptoKey;
  body?: string;
  payload?: string;
  isValid?: boolean;
}

export interface VerificationStep {
  readonly name: string;
  execute(ctx: VerificationContext): Promise<VerificationContext>;
}

export class VerificationPipeline {
  constructor(private readonly steps: VerificationStep[]) {}

  async run(initialContext: VerificationContext): Promise<VerificationContext> {
    let context = initialContext;
    for (const step of this.steps) {
      context = await step.execute(context);
    }
    return context;
  }
}
