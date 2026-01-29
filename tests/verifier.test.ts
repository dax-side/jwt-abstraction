/**
 * RED Phase: Token Verification Tests
 * These tests will fail until we implement src/verifier.ts
 */

import * as jwt from 'jsonwebtoken';

describe('Token Verifier', () => {
  const SECRET = 'test-secret-key-for-verification';
  const originalEnv = process.env;

  beforeEach(() => {
    jest.resetModules();
    process.env = { ...originalEnv, JWT_SECRET: SECRET };
  });

  afterEach(() => {
    process.env = originalEnv;
  });

  describe('verifyToken', () => {
    it('should verify and decode a valid token', async () => {
      const { verifyToken } = require('../src/verifier');

      const payload = { userId: 123, email: 'test@example.com', type: 'access' };
      const token = jwt.sign(payload, SECRET, { expiresIn: '15m' });

      const decoded = await verifyToken(token);

      expect(decoded.userId).toBe(123);
      expect(decoded.email).toBe('test@example.com');
      expect(decoded.type).toBe('access');
      expect(decoded.iat).toBeDefined();
      expect(decoded.exp).toBeDefined();
    });

    it('should verify token with custom secret', async () => {
      const { verifyToken } = require('../src/verifier');

      const customSecret = 'different-secret';
      const payload = { userId: 456, type: 'access' };
      const token = jwt.sign(payload, customSecret, { expiresIn: '15m' });

      const decoded = await verifyToken(token, { secret: customSecret });

      expect(decoded.userId).toBe(456);
    });

    it('should throw TokenExpiredError for expired token', async () => {
      const { verifyToken } = require('../src/verifier');
      const { TokenExpiredError } = require('../src/errors');

      // Create an already-expired token (backdated)
      const token = jwt.sign(
        { userId: 123, type: 'access' },
        SECRET,
        { expiresIn: '1ms' }, // Expires immediately
      );

      // Wait a bit to ensure expiration
      await new Promise((resolve) => setTimeout(resolve, 10));

      await expect(verifyToken(token)).rejects.toThrow(TokenExpiredError);
      await expect(verifyToken(token)).rejects.toThrow('jwt expired');
    });

    it('should throw InvalidTokenError for malformed token', async () => {
      const { verifyToken } = require('../src/verifier');
      const { InvalidTokenError } = require('../src/errors');

      await expect(verifyToken('not.a.validtoken')).rejects.toThrow(InvalidTokenError);
      await expect(verifyToken('completely invalid')).rejects.toThrow(InvalidTokenError);
      await expect(verifyToken('')).rejects.toThrow(InvalidTokenError);
    });

    it('should throw InvalidTokenError for tampered token', async () => {
      const { verifyToken } = require('../src/verifier');
      const { InvalidTokenError } = require('../src/errors');

      const validToken = jwt.sign({ userId: 123, type: 'access' }, SECRET, { expiresIn: '15m' });

      // Tamper with the token by changing a character
      const tamperedToken = validToken.slice(0, -5) + 'XXXXX';

      await expect(verifyToken(tamperedToken)).rejects.toThrow(InvalidTokenError);
    });

    it('should throw InvalidTokenError when secret is wrong', async () => {
      const { verifyToken } = require('../src/verifier');
      const { InvalidTokenError } = require('../src/errors');

      const token = jwt.sign({ userId: 123, type: 'access' }, SECRET, { expiresIn: '15m' });

      await expect(verifyToken(token, { secret: 'wrong-secret' })).rejects.toThrow(
        InvalidTokenError,
      );
    });

    it('should throw InvalidTokenError when algorithm mismatch', async () => {
      const { verifyToken } = require('../src/verifier');
      const { InvalidTokenError } = require('../src/errors');

      // Sign with HS512
      const token = jwt.sign({ userId: 123, type: 'access' }, SECRET, {
        algorithm: 'HS512',
        expiresIn: '15m',
      });

      // Try to verify with HS256 (should fail)
      await expect(verifyToken(token, { algorithm: 'HS256' })).rejects.toThrow(InvalidTokenError);
    });

    it('should throw NoSecretError when no secret provided and env not set', async () => {
      delete process.env.JWT_SECRET;
      jest.resetModules();

      const { verifyToken } = require('../src/verifier');
      const { NoSecretError } = require('../src/errors');

      const token = jwt.sign({ userId: 123, type: 'access' }, SECRET, { expiresIn: '15m' });

      await expect(verifyToken(token)).rejects.toThrow(NoSecretError);
    });

    it('should validate issuer if provided in options', async () => {
      const { verifyToken } = require('../src/verifier');
      const { InvalidTokenError } = require('../src/errors');

      const token = jwt.sign({ userId: 123, type: 'access' }, SECRET, {
        issuer: 'my-app',
        expiresIn: '15m',
      });

      // Valid issuer
      const decoded = await verifyToken(token, { issuer: 'my-app' });
      expect(decoded.iss).toBe('my-app');

      // Wrong issuer
      await expect(verifyToken(token, { issuer: 'wrong-app' })).rejects.toThrow(InvalidTokenError);
    });

    it('should validate audience if provided in options', async () => {
      const { verifyToken } = require('../src/verifier');
      const { InvalidTokenError } = require('../src/errors');

      const token = jwt.sign({ userId: 123, type: 'access' }, SECRET, {
        audience: 'my-users',
        expiresIn: '15m',
      });

      // Valid audience
      const decoded = await verifyToken(token, { audience: 'my-users' });
      expect(decoded.aud).toBe('my-users');

      // Wrong audience
      await expect(verifyToken(token, { audience: 'wrong-users' })).rejects.toThrow(
        InvalidTokenError,
      );
    });
  });

  describe('verifyTokenType', () => {
    it('should verify token has expected type', async () => {
      const { verifyToken } = require('../src/verifier');

      const accessToken = jwt.sign({ userId: 123, type: 'access' }, SECRET, { expiresIn: '15m' });
      const refreshToken = jwt.sign({ userId: 123, type: 'refresh' }, SECRET, { expiresIn: '7d' });

      const accessDecoded = await verifyToken(accessToken, { expectedType: 'access' });
      expect(accessDecoded.type).toBe('access');

      const refreshDecoded = await verifyToken(refreshToken, { expectedType: 'refresh' });
      expect(refreshDecoded.type).toBe('refresh');
    });

    it('should throw InvalidTokenError when type does not match', async () => {
      const { verifyToken } = require('../src/verifier');
      const { InvalidTokenError } = require('../src/errors');

      const accessToken = jwt.sign({ userId: 123, type: 'access' }, SECRET, { expiresIn: '15m' });

      // Try to verify access token as refresh token
      await expect(verifyToken(accessToken, { expectedType: 'refresh' })).rejects.toThrow(
        InvalidTokenError,
      );
      await expect(verifyToken(accessToken, { expectedType: 'refresh' })).rejects.toThrow(
        'Token type mismatch',
      );
    });

    it('should throw InvalidTokenError when type claim is missing', async () => {
      const { verifyToken } = require('../src/verifier');
      const { InvalidTokenError } = require('../src/errors');

      // Create token without type claim
      const tokenWithoutType = jwt.sign({ userId: 123 }, SECRET, { expiresIn: '15m' });

      await expect(verifyToken(tokenWithoutType, { expectedType: 'access' })).rejects.toThrow(
        InvalidTokenError,
      );
      await expect(verifyToken(tokenWithoutType, { expectedType: 'access' })).rejects.toThrow(
        'Token type mismatch',
      );
    });

    it('should handle non-Error thrown objects', async () => {
      // Mock jwt.verify to throw a non-Error object
      const originalVerify = require('jsonwebtoken').verify;
      jest.spyOn(require('jsonwebtoken'), 'verify').mockImplementation(() => {
        throw 'string error'; // eslint-disable-line no-throw-literal
      });

      const { verifyToken } = require('../src/verifier');
      const { InvalidTokenError } = require('../src/errors');

      const token = 'some.jwt.token';

      await expect(verifyToken(token)).rejects.toThrow(InvalidTokenError);
      await expect(verifyToken(token)).rejects.toThrow(
        'Token verification failed with unknown error',
      );

      // Restore
      require('jsonwebtoken').verify = originalVerify;
    });

    it('should handle generic Error objects from jwt.verify', async () => {
      // Mock jwt.verify to throw a generic Error
      const originalVerify = require('jsonwebtoken').verify;
      jest.spyOn(require('jsonwebtoken'), 'verify').mockImplementation(() => {
        throw new Error('Some generic error message');
      });

      const { verifyToken } = require('../src/verifier');
      const { InvalidTokenError } = require('../src/errors');

      const token = 'some.jwt.token';

      await expect(verifyToken(token)).rejects.toThrow(InvalidTokenError);
      await expect(verifyToken(token)).rejects.toThrow(
        'Token verification failed: Some generic error message',
      );

      // Restore
      require('jsonwebtoken').verify = originalVerify;
    });
  });
});
