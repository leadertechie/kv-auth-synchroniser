export class Identity {
  constructor(
    public readonly caller: string,
    public readonly userEmail: string = ""
  ) {
    if (!caller) {
      throw new Error("Identity caller cannot be empty");
    }
  }

  toString(): string {
    return `${this.caller}:${this.userEmail}`;
  }

  static fromHeaders(caller: string | null, userEmail: string | null): Identity {
    if (!caller) {
      throw new Error("Missing caller in headers");
    }
    return new Identity(caller, userEmail || "");
  }
}
