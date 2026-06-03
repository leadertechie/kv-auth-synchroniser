import type { Identity } from "../core/identity";
import type { Algorithm } from "../algorithms/types";
import type { PublicKeyRegistry } from "../registry/types";
import type { LoggerInterface } from "@leadertechie/telemetry";

export interface VerificationContext {
  readonly request: Request;
  readonly algorithm: Algorithm;
  readonly registry: PublicKeyRegistry;
  readonly logger?: LoggerInterface;
  
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
  constructor(
    private readonly steps: VerificationStep[],
    private readonly logger?: LoggerInterface
  ) {}

  async run(initialContext: VerificationContext): Promise<VerificationContext> {
    let context = initialContext;
    for (const step of this.steps) {
      this.logger?.debug?.(`Running verification step: ${step.name}`, {
        caller: context.identity?.caller,
        path: context.path
      });
      context = await step.execute(context);
    }
    return context;
  }
}
