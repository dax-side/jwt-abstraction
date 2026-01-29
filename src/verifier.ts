import * as jwt from 'jsonwebtoken';
import { TokenExpiredError, InvalidTokenError, NoSecretError } from './errors';
import { JwtOptions, JwtPayload, TokenType } from './types';
import { resolveSecret } from './config';

export interface VerifyOptions extends JwtOptions {
  expectedType?: TokenType;
}

export async function verifyToken(token: string, options?: VerifyOptions): Promise<JwtPayload> {
  const decoded = jwt.decode(token) as JwtPayload | null;
  const tokenType = decoded?.type || 'access';
  
  const secret = resolveSecret(options, tokenType as 'access' | 'refresh');

  const verifyOptions: jwt.VerifyOptions = {};

  if (options?.algorithm) {
    verifyOptions.algorithms = [options.algorithm];
  }
  if (options?.issuer) {
    verifyOptions.issuer = options.issuer;
  }
  if (options?.audience) {
    verifyOptions.audience = options.audience;
  }

  try {
    const verified = jwt.verify(token, secret, verifyOptions) as JwtPayload;

    if (options?.expectedType) {
      if (!verified.type) {
        throw new InvalidTokenError('Token type mismatch: type claim is missing');
      }
      if (verified.type !== options.expectedType) {
        throw new InvalidTokenError(
          `Token type mismatch: expected '${options.expectedType}', got '${verified.type}'`,
        );
      }
    }

    return verified;
  } catch (error) {
    if (
      error instanceof TokenExpiredError ||
      error instanceof InvalidTokenError ||
      error instanceof NoSecretError
    ) {
      throw error;
    }

    if (error instanceof Error) {
      if (error.name === 'TokenExpiredError') {
        throw new TokenExpiredError(error.message);
      }
      if (
        error.name === 'JsonWebTokenError' ||
        error.name === 'NotBeforeError' ||
        error.message.includes('invalid')
      ) {
        throw new InvalidTokenError(error.message);
      }

      throw new InvalidTokenError(`Token verification failed: ${error.message}`);
    }

    throw new InvalidTokenError('Token verification failed with unknown error');
  }
}
