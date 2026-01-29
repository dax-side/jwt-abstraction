/**
 * Tests for configuration module
 */

describe('Configuration Module', () => {
  let DEFAULTS: typeof import('../src/config').DEFAULTS;
  let resolveSecret: typeof import('../src/config').resolveSecret;
  let mergeOptions: typeof import('../src/config').mergeOptions;
  let NoSecretError: typeof import('../src/errors').NoSecretError;

  beforeEach(() => {
    delete process.env.JWT_SECRET;
    jest.resetModules();

    // Fresh imports for each test
    const config = require('../src/config');
    const errors = require('../src/errors');

    DEFAULTS = config.DEFAULTS;
    resolveSecret = config.resolveSecret;
    mergeOptions = config.mergeOptions;
    NoSecretError = errors.NoSecretError;
  });

  describe('DEFAULTS', () => {
    it('should export default configuration values', () => {
      expect(DEFAULTS).toEqual({
        algorithm: 'HS256',
        accessTokenTTL: '15m',
        refreshTokenTTL: '7d',
      });
    });
  });

  describe('resolveSecret', () => {
    it('should return secret from options', () => {
      const secret = resolveSecret({ secret: 'test-secret' });
      expect(secret).toBe('test-secret');
    });

    it('should return secret from environment when not in options', () => {
      process.env.JWT_SECRET = 'env-secret';
      const secret = resolveSecret();
      expect(secret).toBe('env-secret');
    });

    it('should prefer options secret over environment', () => {
      process.env.JWT_SECRET = 'env-secret';
      const secret = resolveSecret({ secret: 'options-secret' });
      expect(secret).toBe('options-secret');
    });

    it('should throw NoSecretError when no secret available', () => {
      expect(() => resolveSecret()).toThrow(NoSecretError);
      expect(() => resolveSecret()).toThrow('JWT_SECRET environment variable is not set');
    });

    it('should throw NoSecretError for refresh tokens when no secret available', () => {
      delete process.env.JWT_SECRET;
      delete process.env.JWT_REFRESH_SECRET;
      expect(() => resolveSecret({}, 'refresh')).toThrow(NoSecretError);
      expect(() => resolveSecret({}, 'refresh')).toThrow('JWT_REFRESH_SECRET or JWT_SECRET environment variable is not set');
    });

    it('should use refreshTokenSecret for refresh tokens', () => {
      const secret = resolveSecret({ secret: 'access-secret', refreshTokenSecret: 'refresh-secret' }, 'refresh');
      expect(secret).toBe('refresh-secret');
    });

    it('should use JWT_REFRESH_SECRET env for refresh tokens', () => {
      process.env.JWT_REFRESH_SECRET = 'env-refresh-secret';
      process.env.JWT_SECRET = 'env-access-secret';
      const secret = resolveSecret({}, 'refresh');
      expect(secret).toBe('env-refresh-secret');
    });

    it('should fall back to JWT_SECRET for refresh tokens if JWT_REFRESH_SECRET not set', () => {
      delete process.env.JWT_REFRESH_SECRET;
      process.env.JWT_SECRET = 'env-secret';
      const secret = resolveSecret({}, 'refresh');
      expect(secret).toBe('env-secret');
    });

    it('should prefer refreshTokenSecret option over environment', () => {
      process.env.JWT_REFRESH_SECRET = 'env-refresh';
      const secret = resolveSecret({ refreshTokenSecret: 'option-refresh' }, 'refresh');
      expect(secret).toBe('option-refresh');
    });
  });

  describe('mergeOptions', () => {
    beforeEach(() => {
      process.env.JWT_SECRET = 'test-secret';
      delete process.env.JWT_REFRESH_SECRET;
    });

    it('should merge with defaults when no options provided', () => {
      const merged = mergeOptions();
      expect(merged).toEqual({
        secret: 'test-secret',
        refreshTokenSecret: undefined,
        algorithm: 'HS256',
        accessTokenTTL: '15m',
        refreshTokenTTL: '7d',
        issuer: undefined,
        audience: undefined,
      });
    });

    it('should preserve custom options', () => {
      const merged = mergeOptions({
        secret: 'custom-secret',
        refreshTokenSecret: 'custom-refresh',
        algorithm: 'HS512',
        accessTokenTTL: '30m',
        refreshTokenTTL: '14d',
      });
      expect(merged).toEqual({
        secret: 'custom-secret',
        refreshTokenSecret: 'custom-refresh',
        algorithm: 'HS512',
        accessTokenTTL: '30m',
        refreshTokenTTL: '14d',
        issuer: undefined,
        audience: undefined,
      });
    });

    it('should merge partial options with defaults', () => {
      const merged = mergeOptions({
        accessTokenTTL: '1h',
      });
      expect(merged).toEqual({
        secret: 'test-secret',
        refreshTokenSecret: undefined,
        algorithm: 'HS256',
        accessTokenTTL: '1h',
        refreshTokenTTL: '7d',
        issuer: undefined,
        audience: undefined,
      });
    });

    it('should include issuer and audience when provided', () => {
      const merged = mergeOptions({
        issuer: 'my-app',
        audience: 'my-users',
      });
      expect(merged).toEqual({
        secret: 'test-secret',
        refreshTokenSecret: undefined,
        algorithm: 'HS256',
        accessTokenTTL: '15m',
        refreshTokenTTL: '7d',
        issuer: 'my-app',
        audience: 'my-users',
      });
    });

    it('should include refreshTokenSecret from environment', () => {
      process.env.JWT_REFRESH_SECRET = 'env-refresh-secret';
      const merged = mergeOptions();
      expect(merged.refreshTokenSecret).toBe('env-refresh-secret');
    });
  });
});
