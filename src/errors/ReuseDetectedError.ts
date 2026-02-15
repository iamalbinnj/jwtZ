export class ReuseDetectedError extends Error {
  constructor() {
    super("Refresh token reuse detected");
    this.name = "ReuseDetectedError";
  }
}
