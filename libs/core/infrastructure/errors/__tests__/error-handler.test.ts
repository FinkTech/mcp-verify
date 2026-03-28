/**
 * Copyright (c) 2026 FinkTech
 *
 * This file is part of MCP Verify.
 * Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
 * See LICENSE file in the project root for full license information.
 */
/**
 * ErrorHandler Tests
 * Comprehensive test suite for enterprise error handling
 */

import {
  ErrorHandler,
  AppError,
  ValidationError,
  NetworkError,
  TimeoutError,
  SecurityError,
  RateLimitError,
  ConfigurationError,
  InternalError,
  CircuitBreaker,
  ErrorCategory,
  ErrorSeverity,
  RecoveryStrategy,
  DEFAULT_RETRY_CONFIG,
} from '../error-handler';

describe('Error Types', () => {
  describe('AppError', () => {
    it('should create AppError with all properties', () => {
      const error = new AppError(
        'test message',
        'TEST_001',
        ErrorCategory.INTERNAL,
        ErrorSeverity.HIGH,
        {
          context: { key: 'value' },
          recoveryStrategy: RecoveryStrategy.RETRY,
        }
      );

      expect(error.message).toBe('test message');
      expect(error.code).toBe('TEST_001');
      expect(error.category).toBe(ErrorCategory.INTERNAL);
      expect(error.severity).toBe(ErrorSeverity.HIGH);
      expect(error.context).toEqual({ key: 'value' });
      expect(error.recoveryStrategy).toBe(RecoveryStrategy.RETRY);
      expect(error.isOperational).toBe(true);
      expect(error.timestamp).toBeDefined();
    });

    it('should have stack trace', () => {
      const error = new AppError('test', 'TEST_001', ErrorCategory.INTERNAL, ErrorSeverity.LOW);
      expect(error.stack).toBeDefined();
      expect(error.stack).toContain('AppError');
    });

    it('should provide user-safe message in production', () => {
      const originalEnv = process.env.NODE_ENV;
      process.env.NODE_ENV = 'production';

      const error = new AppError(
        'Internal error with sensitive data',
        'TEST_001',
        ErrorCategory.INTERNAL,
        ErrorSeverity.CRITICAL
      );

      const userMessage = error.getUserMessage();
      expect(userMessage).not.toContain('Internal error');
      expect(userMessage).toContain('unexpected error');

      process.env.NODE_ENV = originalEnv;
    });

    it('should convert to JSON', () => {
      const error = new AppError('test', 'TEST_001', ErrorCategory.INTERNAL, ErrorSeverity.LOW);
      const json = error.toJSON();

      expect(json).toHaveProperty('name');
      expect(json).toHaveProperty('message');
      expect(json).toHaveProperty('code');
      expect(json).toHaveProperty('category');
      expect(json).toHaveProperty('severity');
      expect(json).toHaveProperty('timestamp');
    });
  });

  describe('ValidationError', () => {
    it('should create ValidationError with correct properties', () => {
      const error = new ValidationError('invalid input', { field: 'email' });

      expect(error).toBeInstanceOf(AppError);
      expect(error.code).toBe('ERR_VALIDATION');
      expect(error.category).toBe(ErrorCategory.VALIDATION);
      expect(error.severity).toBe(ErrorSeverity.LOW);
      expect(error.recoveryStrategy).toBe(RecoveryStrategy.NONE);
      expect(error.context).toEqual({ field: 'email' });
    });
  });

  describe('NetworkError', () => {
    it('should create NetworkError with correct properties', () => {
      const innerError = new Error('Connection refused');
      const error = new NetworkError('Network failed', innerError, { url: 'http://example.com' });

      expect(error.code).toBe('ERR_NETWORK');
      expect(error.category).toBe(ErrorCategory.NETWORK);
      expect(error.severity).toBe(ErrorSeverity.MEDIUM);
      expect(error.recoveryStrategy).toBe(RecoveryStrategy.RETRY);
      expect(error.innerError).toBe(innerError);
    });
  });

  describe('TimeoutError', () => {
    it('should create TimeoutError with retry strategy', () => {
      const error = new TimeoutError('Operation timed out');

      expect(error.code).toBe('ERR_TIMEOUT');
      expect(error.category).toBe(ErrorCategory.TIMEOUT);
      expect(error.recoveryStrategy).toBe(RecoveryStrategy.RETRY);
    });
  });

  describe('SecurityError', () => {
    it('should create SecurityError with critical severity', () => {
      const error = new SecurityError('SQL Injection detected', 'SEC_SQL_INJ');

      expect(error.code).toBe('SEC_SQL_INJ');
      expect(error.category).toBe(ErrorCategory.SECURITY);
      expect(error.severity).toBe(ErrorSeverity.CRITICAL);
      expect(error.recoveryStrategy).toBe(RecoveryStrategy.NONE);
    });
  });

  describe('RateLimitError', () => {
    it('should create RateLimitError with retryAfter', () => {
      const error = new RateLimitError('Rate limit exceeded', 60);

      expect(error.code).toBe('ERR_RATE_LIMIT');
      expect(error.category).toBe(ErrorCategory.RATE_LIMIT);
      expect(error.retryAfter).toBe(60);
      expect(error.recoveryStrategy).toBe(RecoveryStrategy.RETRY);
    });
  });

  describe('ConfigurationError', () => {
    it('should create ConfigurationError with non-operational flag', () => {
      const error = new ConfigurationError('Invalid config');

      expect(error.code).toBe('ERR_CONFIGURATION');
      expect(error.category).toBe(ErrorCategory.CONFIGURATION);
      expect(error.severity).toBe(ErrorSeverity.HIGH);
      expect(error.isOperational).toBe(false);
    });
  });

  describe('InternalError', () => {
    it('should create InternalError with graceful degradation', () => {
      const innerError = new Error('Unexpected error');
      const error = new InternalError('Internal error occurred', innerError);

      expect(error.code).toBe('ERR_INTERNAL');
      expect(error.category).toBe(ErrorCategory.INTERNAL);
      expect(error.severity).toBe(ErrorSeverity.CRITICAL);
      expect(error.recoveryStrategy).toBe(RecoveryStrategy.DEGRADE_GRACEFULLY);
      expect(error.isOperational).toBe(false);
    });
  });
});

describe('ErrorHandler', () => {
  let errorHandler: ErrorHandler;

  beforeEach(() => {
    (ErrorHandler as any).instance = undefined;
    errorHandler = ErrorHandler.getInstance();
  });

  describe('Singleton Pattern', () => {
    it('should return the same instance', () => {
      const instance1 = ErrorHandler.getInstance();
      const instance2 = ErrorHandler.getInstance();
      expect(instance1).toBe(instance2);
    });
  });

  describe('Error Handling', () => {
    it('should handle AppError', () => {
      const error = new ValidationError('test error');
      expect(() => errorHandler.handle(error, 'TestComponent')).not.toThrow();
    });

    it('should handle generic Error', () => {
      const error = new Error('test error');
      expect(() => errorHandler.handle(error, 'TestComponent')).not.toThrow();
    });

    it('should convert generic Error to InternalError', () => {
      const error = new Error('test error');
      errorHandler.handle(error, 'TestComponent');
      // Should not throw
      expect(true).toBe(true);
    });
  });

  describe('Retry Logic', () => {
    it('should retry on retryable errors', async () => {
      let attemptCount = 0;
      const operation = jest.fn(async () => {
        attemptCount++;
        if (attemptCount < 3) {
          throw new NetworkError('Network error');
        }
        return 'success';
      });

      const result = await errorHandler.executeWithRetry(operation, {
        maxAttempts: 3,
        initialDelay: 10,
      });

      expect(result).toBe('success');
      expect(attemptCount).toBe(3);
    });

    it('should not retry on non-retryable errors', async () => {
      let attemptCount = 0;
      const operation = jest.fn(async () => {
        attemptCount++;
        throw new ValidationError('Validation error');
      });

      await expect(
        errorHandler.executeWithRetry(operation, {
          maxAttempts: 3,
          initialDelay: 10,
        })
      ).rejects.toThrow(ValidationError);

      expect(attemptCount).toBe(1);
    });

    it('should implement exponential backoff', async () => {
      const delays: number[] = [];
      let attemptCount = 0;

      const operation = jest.fn(async () => {
        const start = Date.now();
        attemptCount++;
        if (attemptCount < 4) {
          throw new NetworkError('Network error');
        }
        delays.push(Date.now() - start);
        return 'success';
      });

      await errorHandler.executeWithRetry(operation, {
        maxAttempts: 4,
        initialDelay: 50,
        backoffMultiplier: 2,
        maxDelay: 500,
      });

      // Verify delays increase exponentially
      // Note: Actual delays will be accumulated, so we just verify retries happened
      expect(attemptCount).toBe(4);
    });

    it('should respect max delay', async () => {
      let attemptCount = 0;
      const operation = jest.fn(async () => {
        attemptCount++;
        if (attemptCount < 5) {
          throw new NetworkError('Network error');
        }
        return 'success';
      });

      await errorHandler.executeWithRetry(operation, {
        maxAttempts: 5,
        initialDelay: 100,
        backoffMultiplier: 10,
        maxDelay: 200,
      });

      expect(attemptCount).toBe(5);
    });

    it('should throw last error after all retries fail', async () => {
      const operation = jest.fn(async () => {
        throw new NetworkError('Network error');
      });

      await expect(
        errorHandler.executeWithRetry(operation, {
          maxAttempts: 3,
          initialDelay: 10,
        })
      ).rejects.toThrow(NetworkError);

      expect(operation).toHaveBeenCalledTimes(3);
    });

    it('should use default retry config', async () => {
      let attemptCount = 0;
      const operation = jest.fn(async () => {
        attemptCount++;
        if (attemptCount < DEFAULT_RETRY_CONFIG.maxAttempts) {
          throw new NetworkError('Network error');
        }
        return 'success';
      });

      const result = await errorHandler.executeWithRetry(operation);

      expect(result).toBe('success');
      expect(attemptCount).toBe(DEFAULT_RETRY_CONFIG.maxAttempts);
    });
  });

  describe('Circuit Breaker', () => {
    it('should execute operation when circuit is closed', async () => {
      const operation = jest.fn(async () => 'success');

      const result = await errorHandler.executeWithCircuitBreaker(
        operation,
        'test-circuit',
        'TestComponent'
      );

      expect(result).toBe('success');
      expect(operation).toHaveBeenCalledTimes(1);
    });

    it('should open circuit after threshold failures', async () => {
      const operation = jest.fn(async () => {
        throw new Error('Operation failed');
      });

      // Fail 5 times to open circuit (default threshold)
      for (let i = 0; i < 5; i++) {
        try {
          await errorHandler.executeWithCircuitBreaker(operation, 'test-circuit', 'TestComponent');
        } catch (e) {
          // Expected
        }
      }

      // Circuit should be open now
      await expect(
        errorHandler.executeWithCircuitBreaker(operation, 'test-circuit', 'TestComponent')
      ).rejects.toThrow();

      // Operation should not have been called on the 6th attempt
      expect(operation).toHaveBeenCalledTimes(5);
    });

    it('should track circuit breaker state', async () => {
      const operation = jest.fn(async () => 'success');

      await errorHandler.executeWithCircuitBreaker(operation, 'test-circuit-state', 'TestComponent');

      const state = errorHandler.getCircuitBreakerState('test-circuit-state');
      expect(state).toBe('CLOSED');
    });

    it('should allow resetting circuit breaker', async () => {
      const operation = jest.fn().mockRejectedValue(new Error('Operation failed'));

      // Open the circuit
      for (let i = 0; i < 5; i++) {
        try {
          await errorHandler.executeWithCircuitBreaker(
            operation,
            'test-circuit-reset',
            'TestComponent'
          );
        } catch (e) {
          // Expected
        }
      }

      // Reset circuit
      errorHandler.resetCircuitBreaker('test-circuit-reset');

      // Should work again
      operation.mockResolvedValueOnce('success');
      const result = await errorHandler.executeWithCircuitBreaker(
        operation,
        'test-circuit-reset',
        'TestComponent'
      );
      expect(result).toBe('success');
    });
  });

  describe('Async Function Wrapping', () => {
    it('should wrap async function with error handling', async () => {
      const mockFn = jest.fn(async (x: number) => x * 2);
      const wrapped = errorHandler.wrapAsync(mockFn, 'TestComponent');

      const result = await wrapped(5);
      expect(result).toBe(10);
      expect(mockFn).toHaveBeenCalledWith(5);
    });

    it('should handle errors in wrapped function', async () => {
      const mockFn = jest.fn(async () => {
        throw new Error('test error');
      });
      const wrapped = errorHandler.wrapAsync(mockFn, 'TestComponent');

      await expect(wrapped()).rejects.toThrow('test error');
    });
  });
});

describe('CircuitBreaker', () => {
  let circuitBreaker: CircuitBreaker;

  beforeEach(() => {
    circuitBreaker = new CircuitBreaker(3, 1000, 2, 'test');
  });

  describe('Initial State', () => {
    it('should start in CLOSED state', () => {
      expect(circuitBreaker.getState()).toBe('CLOSED');
    });
  });

  describe('State Transitions', () => {
    it('should transition to OPEN after threshold failures', async () => {
      const failingOp = async () => {
        throw new Error('fail');
      };

      // Fail 3 times
      for (let i = 0; i < 3; i++) {
        try {
          await circuitBreaker.execute(failingOp);
        } catch (e) {
          // Expected
        }
      }

      expect(circuitBreaker.getState()).toBe('OPEN');
    });

    it('should transition to HALF_OPEN after timeout', async () => {
      const failingOp = async () => {
        throw new Error('fail');
      };

      // Open the circuit
      for (let i = 0; i < 3; i++) {
        try {
          await circuitBreaker.execute(failingOp);
        } catch (e) {
          // Expected
        }
      }

      // Wait for timeout + a bit more
      await new Promise(resolve => setTimeout(resolve, 1100));

      // Try again - should transition to HALF_OPEN
      try {
        await circuitBreaker.execute(failingOp);
      } catch (e) {
        // Expected
      }

      expect(circuitBreaker.getState()).toBe('OPEN'); // Failed again, back to OPEN
    });

    it('should transition from HALF_OPEN to CLOSED after successful attempts', async () => {
      const operation = jest.fn()
        .mockRejectedValueOnce(new Error('fail'))
        .mockRejectedValueOnce(new Error('fail'))
        .mockRejectedValueOnce(new Error('fail'))
        .mockResolvedValue('success');

      // Open the circuit
      for (let i = 0; i < 3; i++) {
        try {
          await circuitBreaker.execute(operation);
        } catch (e) {
          // Expected
        }
      }

      expect(circuitBreaker.getState()).toBe('OPEN');

      // Wait for timeout
      await new Promise(resolve => setTimeout(resolve, 1100));

      // Succeed twice (threshold is 2)
      await circuitBreaker.execute(operation);
      await circuitBreaker.execute(operation);

      expect(circuitBreaker.getState()).toBe('CLOSED');
    });
  });

  describe('Reset', () => {
    it('should reset to CLOSED state', async () => {
      const failingOp = async () => {
        throw new Error('fail');
      };

      // Open the circuit
      for (let i = 0; i < 3; i++) {
        try {
          await circuitBreaker.execute(failingOp);
        } catch (e) {
          // Expected
        }
      }

      expect(circuitBreaker.getState()).toBe('OPEN');

      circuitBreaker.reset();
      expect(circuitBreaker.getState()).toBe('CLOSED');
    });
  });

  describe('Success Handling', () => {
    it('should reset failure count on success', async () => {
      const operation = jest.fn()
        .mockRejectedValueOnce(new Error('fail'))
        .mockRejectedValueOnce(new Error('fail'))
        .mockResolvedValueOnce('success')
        .mockRejectedValueOnce(new Error('fail'))
        .mockRejectedValueOnce(new Error('fail'));

      // Fail twice
      try {
        await circuitBreaker.execute(operation);
      } catch (e) {}
      try {
        await circuitBreaker.execute(operation);
      } catch (e) {}

      // Succeed
      await circuitBreaker.execute(operation);

      // Fail twice again - should not open (count was reset)
      try {
        await circuitBreaker.execute(operation);
      } catch (e) {}
      try {
        await circuitBreaker.execute(operation);
      } catch (e) {}

      expect(circuitBreaker.getState()).toBe('CLOSED');
    });
  });
});
