/**
 * RED Phase: Token Generation Tests
 * These tests will fail until we implement src/generator.ts and src/types.ts
 */

import * as jwt from 'jsonwebtoken';

describe('Token Generator', () => {
  const originalEnv = process.env;

  beforeEach(() => {
    jest.resetModules();
    process.env = { ...originalEnv };
  });

  afterEach(() => {
    process.env = originalEnv;
  });

  describe('createTokens with zero config', () => {
    it('should throw NoSecretError when JWT_SECRET is not set', () => {
      delete process.env.JWT_SECRET;
      jest.resetModules(); // Reset again after env change

      const { createTokens } = require('../src/generator');
      const { NoSecretError } = require('../src/errors');

      expect(() => {
        createTokens({ userId: 123 });
      }).toThrow(NoSecretError);

      expect(() => {
        createTokens({ userId: 123 });
      }).toThrow('JWT_SECRET environment variable is not set');
    });

    it('should generate access and refresh tokens from env secret', () => {
      process.env.JWT_SECRET = 'test-secret-key';

      const { createTokens } = require('../src/generator');
      const payload = { userId: 123, email: 'test@example.com' };
      const result = createTokens(payload);

      expect(result).toHaveProperty('accessToken');
      expect(result).toHaveProperty('refreshToken');
      expect(typeof result.accessToken).toBe('string');
      expect(typeof result.refreshToken).toBe('string');
      expect(result.accessToken).not.toBe(result.refreshToken);
    });

    it('should create valid JWT tokens decodable by jsonwebtoken', () => {
      process.env.JWT_SECRET = 'test-secret-key';

      const { createTokens } = require('../src/generator');
      const payload = { userId: 123 };
      const result = createTokens(payload);

      // Verify structure without verification (decode only)
      const accessDecoded = jwt.decode(result.accessToken) as any;
      const refreshDecoded = jwt.decode(result.refreshToken) as any;

      expect(accessDecoded).not.toBeNull();
      expect(refreshDecoded).not.toBeNull();
      expect(accessDecoded.userId).toBe(123);
      expect(refreshDecoded.userId).toBe(123);
    });

    it('should include type claim in tokens', () => {
      process.env.JWT_SECRET = 'test-secret-key';

      const { createTokens } = require('../src/generator');
      const result = createTokens({ userId: 123 });

      const accessDecoded = jwt.decode(result.accessToken) as any;
      const refreshDecoded = jwt.decode(result.refreshToken) as any;

      expect(accessDecoded.type).toBe('access');
      expect(refreshDecoded.type).toBe('refresh');
    });

    it('should include standard JWT claims (iat, exp)', () => {
      process.env.JWT_SECRET = 'test-secret-key';

      const { createTokens } = require('../src/generator');
      const result = createTokens({ userId: 123 });

      const accessDecoded = jwt.decode(result.accessToken) as any;
      const refreshDecoded = jwt.decode(result.refreshToken) as any;

      expect(accessDecoded.iat).toBeDefined();
      expect(accessDecoded.exp).toBeDefined();
      expect(refreshDecoded.iat).toBeDefined();
      expect(refreshDecoded.exp).toBeDefined();

      expect(typeof accessDecoded.iat).toBe('number');
      expect(typeof accessDecoded.exp).toBe('number');
      expect(accessDecoded.exp).toBeGreaterThan(accessDecoded.iat);
      expect(refreshDecoded.exp).toBeGreaterThan(refreshDecoded.iat);
    });

    it('should use default TTL of 15m for access token', () => {
      process.env.JWT_SECRET = 'test-secret-key';

      const { createTokens } = require('../src/generator');
      const result = createTokens({ userId: 123 });

      const decoded = jwt.decode(result.accessToken) as any;
      const expectedExpiry = decoded.iat + 15 * 60; // 15 minutes in seconds

      expect(decoded.exp).toBe(expectedExpiry);
    });

    it('should use default TTL of 7d for refresh token', () => {
      process.env.JWT_SECRET = 'test-secret-key';

      const { createTokens } = require('../src/generator');
      const result = createTokens({ userId: 123 });

      const decoded = jwt.decode(result.refreshToken) as any;
      const expectedExpiry = decoded.iat + 7 * 24 * 60 * 60; // 7 days in seconds

      expect(decoded.exp).toBe(expectedExpiry);
    });

    it('should use HS256 algorithm by default', () => {
      process.env.JWT_SECRET = 'test-secret-key';

      const { createTokens } = require('../src/generator');
      const result = createTokens({ userId: 123 });

      const accessHeader = JSON.parse(
        Buffer.from(result.accessToken.split('.')[0], 'base64').toString(),
      );

      expect(accessHeader.alg).toBe('HS256');
    });
  });

  describe('createTokens with custom options', () => {
    it('should accept custom secret', () => {
      const { createTokens } = require('../src/generator');
      const customSecret = 'custom-secret-key';
      const payload = { userId: 123 };

      const result = createTokens(payload, { secret: customSecret });

      // Verify with custom secret
      const decoded = jwt.verify(result.accessToken, customSecret) as any;
      expect(decoded.userId).toBe(123);
    });

    it('should throw NoSecretError when no secret provided and env not set', () => {
      delete process.env.JWT_SECRET;
      jest.resetModules(); // Reset again after env change

      const { NoSecretError } = require('../src/errors');
      const { createTokens } = require('../src/generator');

      expect(() => {
        createTokens({ userId: 123 }, {});
      }).toThrow(NoSecretError);
    });

    it('should accept custom accessTokenTTL', () => {
      process.env.JWT_SECRET = 'test-secret-key';

      const { createTokens } = require('../src/generator');
      const result = createTokens({ userId: 123 }, { accessTokenTTL: '30m' });

      const decoded = jwt.decode(result.accessToken) as any;
      const expectedExpiry = decoded.iat + 30 * 60; // 30 minutes

      expect(decoded.exp).toBe(expectedExpiry);
    });

    it('should accept custom refreshTokenTTL', () => {
      process.env.JWT_SECRET = 'test-secret-key';

      const { createTokens } = require('../src/generator');
      const result = createTokens({ userId: 123 }, { refreshTokenTTL: '14d' });

      const decoded = jwt.decode(result.refreshToken) as any;
      const expectedExpiry = decoded.iat + 14 * 24 * 60 * 60; // 14 days

      expect(decoded.exp).toBe(expectedExpiry);
    });

    it('should accept custom algorithm', () => {
      process.env.JWT_SECRET = 'test-secret-key';

      const { createTokens } = require('../src/generator');
      const result = createTokens({ userId: 123 }, { algorithm: 'HS512' });

      const accessHeader = JSON.parse(
        Buffer.from(result.accessToken.split('.')[0], 'base64').toString(),
      );

      expect(accessHeader.alg).toBe('HS512');
    });

    it('should accept custom issuer and audience', () => {
      process.env.JWT_SECRET = 'test-secret-key';

      const { createTokens } = require('../src/generator');
      const result = createTokens({ userId: 123 }, { issuer: 'my-app', audience: 'my-users' });

      const decoded = jwt.decode(result.accessToken) as any;

      expect(decoded.iss).toBe('my-app');
      expect(decoded.aud).toBe('my-users');
    });

    it('should merge user payload with type claim without overwriting type', () => {
      process.env.JWT_SECRET = 'test-secret-key';

      const { createTokens } = require('../src/generator');
      // Try to override type - should be ignored
      const result = createTokens({ userId: 123, type: 'malicious' });

      const accessDecoded = jwt.decode(result.accessToken) as any;
      const refreshDecoded = jwt.decode(result.refreshToken) as any;

      // Type should still be 'access' and 'refresh', not 'malicious'
      expect(accessDecoded.type).toBe('access');
      expect(refreshDecoded.type).toBe('refresh');
    });
  });

  describe('edge cases', () => {
    it('should handle empty payload object', () => {
      process.env.JWT_SECRET = 'test-secret-key';

      const { createTokens } = require('../src/generator');
      const result = createTokens({});

      const decoded = jwt.decode(result.accessToken) as any;

      expect(decoded.type).toBe('access');
      expect(decoded.iat).toBeDefined();
      expect(decoded.exp).toBeDefined();
    });

    it('should handle complex nested payload', () => {
      process.env.JWT_SECRET = 'test-secret-key';

      const { createTokens } = require('../src/generator');
      const complexPayload = {
        userId: 123,
        roles: ['admin', 'user'],
        meta: { lastLogin: '2026-01-29', preferences: { theme: 'dark' } },
      };

      const result = createTokens(complexPayload);
      const decoded = jwt.decode(result.accessToken) as any;

      expect(decoded.userId).toBe(123);
      expect(decoded.roles).toEqual(['admin', 'user']);
      expect(decoded.meta.preferences.theme).toBe('dark');
    });
  });
});
