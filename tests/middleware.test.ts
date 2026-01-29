/**
 * RED Phase: Express Middleware Tests
 * These tests will fail until we implement src/middleware.ts
 */

import * as jwt from 'jsonwebtoken';

describe('Express Middleware', () => {
  const SECRET = 'test-middleware-secret';
  const originalEnv = process.env;

  beforeEach(() => {
    jest.resetModules();
    process.env = { ...originalEnv, JWT_SECRET: SECRET };
  });

  afterEach(() => {
    process.env = originalEnv;
  });

  // Helper to create mock Express req/res/next
  function createMocks() {
    const req: any = {
      headers: {},
      header: function (name: string) {
        return this.headers[name.toLowerCase()];
      },
    };
    const res: any = {
      statusCode: 200,
      _json: null,
      status: jest.fn().mockReturnThis(),
      json: jest.fn(function (data: any) {
        this._json = data;
        return this;
      }),
    };
    const next = jest.fn();
    return { req, res, next };
  }

  describe('protect middleware', () => {
    it('should attach user to req on valid token', async () => {
      const { protect } = require('../src/middleware');
      const { req, res, next } = createMocks();

      const payload = { userId: 123, email: 'test@example.com', type: 'access' };
      const token = jwt.sign(payload, SECRET, { expiresIn: '15m' });
      req.headers.authorization = `Bearer ${token}`;

      const middleware = protect();
      await middleware(req, res, next);

      expect(req.user).toBeDefined();
      expect(req.user.userId).toBe(123);
      expect(req.user.email).toBe('test@example.com');
      expect(next).toHaveBeenCalledTimes(1);
      expect(next).toHaveBeenCalledWith(); // Called without arguments
      expect(res.status).not.toHaveBeenCalled();
    });

    it('should extract token from Authorization header (case insensitive)', async () => {
      const { protect } = require('../src/middleware');
      const { req, res, next } = createMocks();

      const token = jwt.sign({ userId: 456, type: 'access' }, SECRET, { expiresIn: '15m' });
      req.headers.authorization = `bearer ${token}`; // lowercase 'bearer'

      const middleware = protect();
      await middleware(req, res, next);

      expect(req.user).toBeDefined();
      expect(req.user.userId).toBe(456);
      expect(next).toHaveBeenCalled();
    });

    it('should return 401 when Authorization header is missing', async () => {
      const { protect } = require('../src/middleware');
      const { req, res, next } = createMocks();

      // No authorization header
      const middleware = protect();
      await middleware(req, res, next);

      expect(res.status).toHaveBeenCalledWith(401);
      expect(res.json).toHaveBeenCalled();
      expect(res._json).toHaveProperty('error');
      expect(res._json.error).toContain('token');
      expect(next).not.toHaveBeenCalled();
      expect(req.user).toBeUndefined();
    });

    it('should return 401 when Authorization header has no Bearer prefix', async () => {
      const { protect } = require('../src/middleware');
      const { req, res, next } = createMocks();

      const token = jwt.sign({ userId: 123, type: 'access' }, SECRET, { expiresIn: '15m' });
      req.headers.authorization = token; // Missing 'Bearer ' prefix

      const middleware = protect();
      await middleware(req, res, next);

      expect(res.status).toHaveBeenCalledWith(401);
      expect(res._json.error).toContain('token');
      expect(next).not.toHaveBeenCalled();
    });

    it('should return 401 when token is expired', async () => {
      const { protect } = require('../src/middleware');
      const { req, res, next } = createMocks();

      // Create an expired token
      const token = jwt.sign({ userId: 123, type: 'access' }, SECRET, { expiresIn: '1ms' });
      await new Promise((resolve) => setTimeout(resolve, 10)); // Wait for expiration

      req.headers.authorization = `Bearer ${token}`;

      const middleware = protect();
      await middleware(req, res, next);

      expect(res.status).toHaveBeenCalledWith(401);
      expect(res._json.error).toMatch(/expired/i);
      expect(next).not.toHaveBeenCalled();
    });

    it('should return 401 when token is invalid', async () => {
      const { protect } = require('../src/middleware');
      const { req, res, next } = createMocks();

      req.headers.authorization = 'Bearer invalid.token.here';

      const middleware = protect();
      await middleware(req, res, next);

      expect(res.status).toHaveBeenCalledWith(401);
      expect(res._json.error).toMatch(/invalid/i);
      expect(next).not.toHaveBeenCalled();
    });

    it('should return 401 when token is tampered', async () => {
      const { protect } = require('../src/middleware');
      const { req, res, next } = createMocks();

      const validToken = jwt.sign({ userId: 123, type: 'access' }, SECRET, { expiresIn: '15m' });
      const tamperedToken = validToken.slice(0, -5) + 'XXXXX';

      req.headers.authorization = `Bearer ${tamperedToken}`;

      const middleware = protect();
      await middleware(req, res, next);

      expect(res.status).toHaveBeenCalledWith(401);
      expect(next).not.toHaveBeenCalled();
    });

    it('should accept custom secret', async () => {
      const { protect } = require('../src/middleware');
      const { req, res, next } = createMocks();

      const customSecret = 'different-middleware-secret';
      const token = jwt.sign({ userId: 789, type: 'access' }, customSecret, { expiresIn: '15m' });
      req.headers.authorization = `Bearer ${token}`;

      const middleware = protect({ secret: customSecret });
      await middleware(req, res, next);

      expect(req.user.userId).toBe(789);
      expect(next).toHaveBeenCalled();
    });

    it('should validate token type is access by default', async () => {
      const { protect } = require('../src/middleware');
      const { req, res, next } = createMocks();

      // Create a refresh token (not access)
      const refreshToken = jwt.sign({ userId: 123, type: 'refresh' }, SECRET, { expiresIn: '7d' });
      req.headers.authorization = `Bearer ${refreshToken}`;

      const middleware = protect();
      await middleware(req, res, next);

      expect(res.status).toHaveBeenCalledWith(401);
      expect(res._json.error).toMatch(/type/i);
      expect(next).not.toHaveBeenCalled();
    });

    it('should accept custom options (algorithm, issuer, audience)', async () => {
      const { protect } = require('../src/middleware');
      const { req, res, next } = createMocks();

      const token = jwt.sign({ userId: 123, type: 'access' }, SECRET, {
        algorithm: 'HS512',
        issuer: 'my-app',
        audience: 'my-users',
        expiresIn: '15m',
      });
      req.headers.authorization = `Bearer ${token}`;

      const middleware = protect({
        algorithm: 'HS512',
        issuer: 'my-app',
        audience: 'my-users',
      });
      await middleware(req, res, next);

      expect(req.user.userId).toBe(123);
      expect(next).toHaveBeenCalled();
    });

    it('should not include sensitive token data in error responses', async () => {
      const { protect } = require('../src/middleware');
      const { req, res, next } = createMocks();

      req.headers.authorization = 'Bearer malicious.token.data';

      const middleware = protect();
      await middleware(req, res, next);

      expect(res._json.error).not.toContain('malicious.token.data');
    });

    it('should handle errors gracefully and not expose internals', async () => {
      const { req, res, next } = createMocks();

      delete process.env.JWT_SECRET;
      jest.resetModules();
      const { protect: protectNoSecret } = require('../src/middleware');

      const token = jwt.sign({ userId: 123, type: 'access' }, SECRET, { expiresIn: '15m' });
      req.headers.authorization = `Bearer ${token}`;

      const middleware = protectNoSecret();
      await middleware(req, res, next);

      expect(res.status).toHaveBeenCalledWith(401);
      expect(res._json).toHaveProperty('error');
      expect(next).not.toHaveBeenCalled();
    });

    it('should handle unknown errors gracefully', async () => {
      // Mock verifyToken to throw an unknown error
      jest.doMock('../src/verifier', () => ({
        verifyToken: jest.fn().mockRejectedValue(new Error('Unknown error')),
      }));
      jest.resetModules();

      const { protect } = require('../src/middleware');
      const { req, res, next } = createMocks();

      const token = jwt.sign({ userId: 123, type: 'access' }, SECRET, { expiresIn: '15m' });
      req.headers.authorization = `Bearer ${token}`;

      const middleware = protect();
      await middleware(req, res, next);

      expect(res.status).toHaveBeenCalledWith(401);
      expect(res._json.error).toBe('Authentication failed');
      expect(next).not.toHaveBeenCalled();

      // Cleanup
      jest.dontMock('../src/verifier');
    });
  });
});
