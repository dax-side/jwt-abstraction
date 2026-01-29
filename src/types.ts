export type Algorithm = 'HS256' | 'HS384' | 'HS512' | 'RS256' | 'RS384' | 'RS512';

export interface JwtOptions {
  secret?: string;
  refreshTokenSecret?: string;
  algorithm?: Algorithm;
  accessTokenTTL?: string;
  refreshTokenTTL?: string;
  issuer?: string;
  audience?: string;
}

export interface TokenPair {
  accessToken: string;
  refreshToken: string;
}

export type TokenType = 'access' | 'refresh';

export interface JwtPayload {
  type: TokenType;
  iat: number;
  exp: number;
  iss?: string;
  aud?: string;
  [key: string]: any;
}
