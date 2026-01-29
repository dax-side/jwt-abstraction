export class TokenExpiredError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'TokenExpiredError';

    if (Error.captureStackTrace) {
      Error.captureStackTrace(this, TokenExpiredError);
    }
  }
}

export class InvalidTokenError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'InvalidTokenError';
    if (Error.captureStackTrace) {
      Error.captureStackTrace(this, InvalidTokenError);
    }
  }
}

export class NoSecretError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'NoSecretError';
    if (Error.captureStackTrace) {
      Error.captureStackTrace(this, NoSecretError);
    }
  }
}
