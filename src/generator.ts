import * as jwt from 'jsonwebtoken';
import { JwtOptions, TokenPair } from './types';
import { resolveSecret, DEFAULTS } from './config';

export function createTokens(payload: Record<string, any>, options?: JwtOptions): TokenPair {
  const accessSecret = resolveSecret(options, 'access');
  const refreshSecret = resolveSecret(options, 'refresh');
  const algorithm = options?.algorithm || DEFAULTS.algorithm;
  const accessTokenTTL = options?.accessTokenTTL || DEFAULTS.accessTokenTTL;
  const refreshTokenTTL = options?.refreshTokenTTL || DEFAULTS.refreshTokenTTL;

  const baseOptions: jwt.SignOptions = {
    algorithm,
  };

  if (options?.issuer) {
    baseOptions.issuer = options.issuer;
  }
  if (options?.audience) {
    baseOptions.audience = options.audience;
  }

  const accessTokenPayload = {
    ...payload,
    type: 'access',
  };

  const accessToken = jwt.sign(accessTokenPayload, accessSecret, {
    ...baseOptions,
    expiresIn: accessTokenTTL,
  } as jwt.SignOptions);

  const refreshTokenPayload = {
    ...payload,
    type: 'refresh',
  };

  const refreshToken = jwt.sign(refreshTokenPayload, refreshSecret, {
    ...baseOptions,
    expiresIn: refreshTokenTTL,
  } as jwt.SignOptions);

  return {
    accessToken,
    refreshToken,
  };
}
