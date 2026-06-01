export class KVAuthError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "KVAuthError";
  }
}

export class ConfigurationError extends KVAuthError {
  constructor(message: string) {
    super(message);
    this.name = "ConfigurationError";
  }
}

export class VerificationError extends KVAuthError {
  constructor(message: string) {
    super(message);
    this.name = "VerificationError";
  }
}

export class SignatureExpiredError extends VerificationError {
  constructor(timestamp: number) {
    super(`Signature expired. Timestamp: ${timestamp}`);
    this.name = "SignatureExpiredError";
  }
}

export class MissingHeaderError extends VerificationError {
  constructor(header: string) {
    super(`Missing required header: ${header}`);
    this.name = "MissingHeaderError";
  }
}

export class UnknownCallerError extends VerificationError {
  constructor(caller: string) {
    super(`Unknown caller identity: ${caller}`);
    this.name = "UnknownCallerError";
  }
}

export class SignatureMismatchError extends VerificationError {
  constructor() {
    super("Signature verification failed.");
    this.name = "SignatureMismatchError";
  }
}
