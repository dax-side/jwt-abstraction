/**
 * RED Phase: Integration Tests
 * These tests will fail until we implement src/index.ts with useJwt factory
 */

import * as jwt from 'jsonwebtoken';

describe('Integration Tests - useJwt Factory', () => {
  const SECRET = 'test-integration-secret';
  const originalEnv = process.env;

  beforeEach(() => {
    jest.resetModules();
    process.env = { ...originalEnv, JWT_SECRET: SECRET };
  });

  afterEach(() => {
    process.env = originalEnv;
  });

  describe('useJwt() factory', () => {
    it('should return jwt instance with all methods', () => {
      const { useJwt } = require('../src/index');
      const jwtInstance = useJwt();

      expect(jwtInstance).toHaveProperty('create');
      expect(jwtInstance).toHaveProperty('verify');
      expect(jwtInstance).toHaveProperty('protect');
      expect(jwtInstance).toHaveProperty('refresh');
      expect(typeof jwtInstance.create).toBe('function');
      expect(typeof jwtInstance.verify).toBe('function');
      expect(typeof jwtInstance.protect).toBe('function');
      expect(typeof jwtInstance.refresh).toBe('function');
    });

    it('should work with zero configuration', () => {
      const { useJwt } = require('../src/index');
      const jwtInstance = useJwt();

      const tokens = jwtInstance.create({ userId: 123 });

      expect(tokens).toHaveProperty('accessToken');
      expect(tokens).toHaveProperty('refreshToken');
    });

    it('should accept custom options', () => {
      const { useJwt } = require('../src/index');
      const customSecret = 'custom-integration-secret';
      const jwtInstance = useJwt({
        secret: customSecret,
        accessTokenTTL: '30m',
        refreshTokenTTL: '14d',
      });

      const tokens = jwtInstance.create({ userId: 456 });

      // Verify it was signed with custom secret
      const decoded = jwt.decode(tokens.accessToken) as any;
      expect(decoded.userId).toBe(456);

      // Verify with custom secret
      jwt.verify(tokens.accessToken, customSecret);
    });
  });

  describe('End-to-end flow: create → verify → protect', () => {
    it('should complete full auth flow', async () => {
      const { useJwt } = require('../src/index');
      const jwtInstance = useJwt();

      // 1. Create tokens
      const tokens = jwtInstance.create({ userId: 789, role: 'admin' });
      expect(tokens.accessToken).toBeDefined();
      expect(tokens.refreshToken).toBeDefined();

      // 2. Verify access token
      const verified = await jwtInstance.verify(tokens.accessToken);
      expect(verified.userId).toBe(789);
      expect(verified.role).toBe('admin');
      expect(verified.type).toBe('access');

      // 3. Use middleware with token
      const middleware = jwtInstance.protect();
      const req: any = {
        headers: { authorization: `Bearer ${tokens.accessToken}` },
        header: function (name: string) {
          return this.headers[name.toLowerCase()];
        },
      };
      const res: any = {
        status: jest.fn().mockReturnThis(),
        json: jest.fn().mockReturnThis(),
      };
      const next = jest.fn();

      await middleware(req, res, next);

      expect(req.user).toBeDefined();
      expect(req.user.userId).toBe(789);
      expect(req.user.role).toBe('admin');
      expect(next).toHaveBeenCalled();
      expect(res.status).not.toHaveBeenCalled();
    });
  });

  describe('Refresh token flow', () => {
    it('should refresh tokens using refresh token', async () => {
      const { useJwt } = require('../src/index');
      const jwtInstance = useJwt();

      // 1. Create initial tokens
      const initialTokens = jwtInstance.create({ userId: 999, email: 'refresh@test.com' });

      // Wait a moment to ensure different iat (issued at) timestamp
      await new Promise((resolve) => setTimeout(resolve, 1000));

      // 2. Use refresh token to get new tokens
      const newTokens = await jwtInstance.refresh(initialTokens.refreshToken);

      expect(newTokens).toHaveProperty('accessToken');
      expect(newTokens).toHaveProperty('refreshToken');
      expect(newTokens.accessToken).not.toBe(initialTokens.accessToken);
      expect(newTokens.refreshToken).not.toBe(initialTokens.refreshToken);

      // 3. Verify new access token has same payload
      const verified = await jwtInstance.verify(newTokens.accessToken);
      expect(verified.userId).toBe(999);
      expect(verified.email).toBe('refresh@test.com');
    });

    it('should only accept refresh tokens (not access tokens)', async () => {
      const { useJwt } = require('../src/index');
      const { InvalidTokenError } = require('../src/errors');
      const jwtInstance = useJwt();

      const tokens = jwtInstance.create({ userId: 111 });

      // Try to refresh with access token (should fail)
      await expect(jwtInstance.refresh(tokens.accessToken)).rejects.toThrow(InvalidTokenError);
    });

    it('should reject expired refresh tokens', async () => {
      const { useJwt } = require('../src/index');
      const { TokenExpiredError } = require('../src/errors');
      const jwtInstance = useJwt({ refreshTokenTTL: '1ms' });

      const tokens = jwtInstance.create({ userId: 222 });

      // Wait for expiration
      await new Promise((resolve) => setTimeout(resolve, 10));

      await expect(jwtInstance.refresh(tokens.refreshToken)).rejects.toThrow(TokenExpiredError);
    });

    it('should reject invalid refresh tokens', async () => {
      const { useJwt } = require('../src/index');
      const { InvalidTokenError } = require('../src/errors');
      const jwtInstance = useJwt();

      await expect(jwtInstance.refresh('invalid.refresh.token')).rejects.toThrow(InvalidTokenError);
    });
  });

  describe('Multiple instances with different configs', () => {
    it('should support multiple jwt instances with different secrets', async () => {
      const { useJwt } = require('../src/index');

      const jwt1 = useJwt({ secret: 'secret-one' });
      const jwt2 = useJwt({ secret: 'secret-two' });

      const tokens1 = jwt1.create({ app: 'one' });
      const tokens2 = jwt2.create({ app: 'two' });

      // Verify with correct instance
      const verified1 = await jwt1.verify(tokens1.accessToken);
      const verified2 = await jwt2.verify(tokens2.accessToken);

      expect(verified1.app).toBe('one');
      expect(verified2.app).toBe('two');

      // Cross-verification should fail
      const { InvalidTokenError } = require('../src/errors');
      await expect(jwt1.verify(tokens2.accessToken)).rejects.toThrow(InvalidTokenError);
      await expect(jwt2.verify(tokens1.accessToken)).rejects.toThrow(InvalidTokenError);
    });

    it('should support different TTLs per instance', () => {
      const { useJwt } = require('../src/index');

      const shortLived = useJwt({ accessTokenTTL: '5m', refreshTokenTTL: '1d' });
      const longLived = useJwt({ accessTokenTTL: '1h', refreshTokenTTL: '30d' });

      const shortTokens = shortLived.create({ user: 'short' });
      const longTokens = longLived.create({ user: 'long' });

      const shortDecoded = jwt.decode(shortTokens.accessToken) as any;
      const longDecoded = jwt.decode(longTokens.accessToken) as any;

      expect(longDecoded.exp - longDecoded.iat).toBeGreaterThan(
        shortDecoded.exp - shortDecoded.iat,
      );
    });
  });

  describe('Error handling consistency', () => {
    it('should throw same error types across all methods', async () => {
      delete process.env.JWT_SECRET;
      jest.resetModules();

      const { useJwt } = require('../src/index');
      const { NoSecretError } = require('../src/errors');
      const jwtInstance = useJwt();

      // create should throw
      expect(() => jwtInstance.create({ userId: 1 })).toThrow(NoSecretError);

      // verify should throw
      await expect(jwtInstance.verify('some.token.here')).rejects.toThrow(NoSecretError);

      // refresh should throw
      await expect(jwtInstance.refresh('some.token.here')).rejects.toThrow(NoSecretError);
    });
  });

  describe('Separate secrets for access and refresh tokens', () => {
    it('should use different secrets for access and refresh tokens', async () => {
      const ACCESS_SECRET = 'access-only-secret';
      const REFRESH_SECRET = 'refresh-only-secret';

      const { useJwt } = require('../src/index');
      const jwtInstance = useJwt({
        secret: ACCESS_SECRET,
        refreshTokenSecret: REFRESH_SECRET,
      });

      const tokens = jwtInstance.create({ userId: 999 });

      // Access token should be signed with ACCESS_SECRET
      const accessDecoded = jwt.verify(tokens.accessToken, ACCESS_SECRET) as any;
      expect(accessDecoded.userId).toBe(999);
      expect(accessDecoded.type).toBe('access');

      // Access token should NOT verify with REFRESH_SECRET
      expect(() => jwt.verify(tokens.accessToken, REFRESH_SECRET)).toThrow();

      // Refresh token should be signed with REFRESH_SECRET
      const refreshDecoded = jwt.verify(tokens.refreshToken, REFRESH_SECRET) as any;
      expect(refreshDecoded.userId).toBe(999);
      expect(refreshDecoded.type).toBe('refresh');

      // Refresh token should NOT verify with ACCESS_SECRET
      expect(() => jwt.verify(tokens.refreshToken, ACCESS_SECRET)).toThrow();
    });

    it('should verify tokens with correct secret automatically', async () => {
      const ACCESS_SECRET = 'access-secret-2';
      const REFRESH_SECRET = 'refresh-secret-2';

      const { useJwt } = require('../src/index');
      const jwtInstance = useJwt({
        secret: ACCESS_SECRET,
        refreshTokenSecret: REFRESH_SECRET,
      });

      const tokens = jwtInstance.create({ userId: 888 });

      // Verify should automatically use correct secret based on token type
      const accessPayload = await jwtInstance.verify(tokens.accessToken);
      expect(accessPayload.userId).toBe(888);
      expect(accessPayload.type).toBe('access');

      const refreshPayload = await jwtInstance.verify(tokens.refreshToken);
      expect(refreshPayload.userId).toBe(888);
      expect(refreshPayload.type).toBe('refresh');
    });

    it('should fall back to same secret if refreshTokenSecret not provided', async () => {
      const SINGLE_SECRET = 'single-secret-for-both';

      const { useJwt } = require('../src/index');
      const jwtInstance = useJwt({ secret: SINGLE_SECRET });

      const tokens = jwtInstance.create({ userId: 777 });

      // Both tokens should work with the same secret
      const accessDecoded = jwt.verify(tokens.accessToken, SINGLE_SECRET) as any;
      expect(accessDecoded.userId).toBe(777);

      const refreshDecoded = jwt.verify(tokens.refreshToken, SINGLE_SECRET) as any;
      expect(refreshDecoded.userId).toBe(777);
    });

    it('should use JWT_REFRESH_SECRET env variable', async () => {
      process.env.JWT_SECRET = 'env-access-secret';
      process.env.JWT_REFRESH_SECRET = 'env-refresh-secret';
      jest.resetModules();

      const { useJwt } = require('../src/index');
      const jwtInstance = useJwt();

      const tokens = jwtInstance.create({ userId: 666 });

      // Access token uses JWT_SECRET
      const accessDecoded = jwt.verify(tokens.accessToken, 'env-access-secret') as any;
      expect(accessDecoded.userId).toBe(666);

      // Refresh token uses JWT_REFRESH_SECRET
      const refreshDecoded = jwt.verify(tokens.refreshToken, 'env-refresh-secret') as any;
      expect(refreshDecoded.userId).toBe(666);
    });
  });
});
