import { NoSecretError } from './errors';
import { JwtOptions } from './types';

export const DEFAULTS = {
  algorithm: 'HS256' as const,
  accessTokenTTL: '15m',
  refreshTokenTTL: '7d',
} as const;

export function resolveSecret(options?: JwtOptions, tokenType: 'access' | 'refresh' = 'access'): string {
  let secret: string | undefined;

  if (tokenType === 'refresh' && options?.refreshTokenSecret) {
    secret = options.refreshTokenSecret;
  } else if (tokenType === 'refresh' && process.env.JWT_REFRESH_SECRET) {
    secret = process.env.JWT_REFRESH_SECRET;
  } else {
    secret = options?.secret || process.env.JWT_SECRET;
  }

  if (!secret) {
    const envVar = tokenType === 'refresh' ? 'JWT_REFRESH_SECRET or JWT_SECRET' : 'JWT_SECRET';
    throw new NoSecretError(`${envVar} environment variable is not set`);
  }

  return secret;
}
export function mergeOptions(
  options?: JwtOptions,
): Required<Omit<JwtOptions, 'issuer' | 'audience' | 'refreshTokenSecret'>> & Pick<JwtOptions, 'issuer' | 'audience' | 'refreshTokenSecret'> {
  return {
    secret: resolveSecret(options, 'access'),
    refreshTokenSecret: options?.refreshTokenSecret || process.env.JWT_REFRESH_SECRET,
    algorithm: options?.algorithm || DEFAULTS.algorithm,
    accessTokenTTL: options?.accessTokenTTL || DEFAULTS.accessTokenTTL,
    refreshTokenTTL: options?.refreshTokenTTL || DEFAULTS.refreshTokenTTL,
    issuer: options?.issuer,
    audience: options?.audience,
  };
}
