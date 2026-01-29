import { createTokens } from './generator';
import { verifyToken, VerifyOptions } from './verifier';
import { protect } from './middleware';
import { JwtOptions, TokenPair, JwtPayload } from './types';

export interface JwtInstance {
  create(payload: Record<string, any>): TokenPair;
  verify(token: string): Promise<JwtPayload>;
  protect(): ReturnType<typeof protect>;
  refresh(refreshToken: string): Promise<TokenPair>;
}

export function useJwt(options?: JwtOptions): JwtInstance {
  return {
    create(payload: Record<string, any>): TokenPair {
      return createTokens(payload, options);
    },

    async verify(token: string): Promise<JwtPayload> {
      return verifyToken(token, options);
    },

    protect() {
      return protect(options);
    },

    async refresh(refreshToken: string): Promise<TokenPair> {

      const verifyOpts: VerifyOptions = {
        ...options,
        expectedType: 'refresh',
      };

      const decoded = await verifyToken(refreshToken, verifyOpts);

      const { iat: _iat, exp: _exp, nbf: _nbf, iss: _iss, aud: _aud, type: _type, ...userPayload } = decoded;
      return createTokens(userPayload, options);
    },
  };
}

export * from './types';
export * from './errors';
export { protect } from './middleware';
export { createTokens } from './generator';
export { verifyToken } from './verifier';
export { DEFAULTS, resolveSecret, mergeOptions } from './config';
