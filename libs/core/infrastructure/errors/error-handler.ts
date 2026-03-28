/**
 * Copyright (c) 2026 FinkTech
 *
 * This file is part of MCP Verify.
 * Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
 * See LICENSE file in the project root for full license information.
 */
/**
 * Enterprise Error Handling Framework
 *
 * Features:
 * - Standardized error types with error codes
 * - Error classification and severity levels
 * - Automatic logging and auditing
 * - Error recovery strategies
 * - Circuit breaker pattern
 * - Retry mechanisms with exponential backoff
 * - Error context preservation
 * - Security-conscious error messages
 *
 * Standards compliance:
 * - OWASP Error Handling
 * - CWE-209: Information Exposure Through an Error Message
 * - CWE-755: Improper Handling of Exceptional Conditions
 *
 * @module libs/core/infrastructure/errors
 */

import { Logger, AuditEventType, createScopedLogger } from '../logging/logger';

/**
 * Error categories for classification
 */
export enum ErrorCategory {
  VALIDATION = 'VALIDATION',
  AUTHENTICATION = 'AUTHENTICATION',
  AUTHORIZATION = 'AUTHORIZATION',
  NETWORK = 'NETWORK',
  TIMEOUT = 'TIMEOUT',
  SECURITY = 'SECURITY',
  RATE_LIMIT = 'RATE_LIMIT',
  CONFIGURATION = 'CONFIGURATION',
  INTERNAL = 'INTERNAL',
  EXTERNAL = 'EXTERNAL',
  DATA = 'DATA'
}

/**
 * Error severity levels
 */
export enum ErrorSeverity {
  LOW = 'LOW',
  MEDIUM = 'MEDIUM',
  HIGH = 'HIGH',
  CRITICAL = 'CRITICAL'
}

/**
 * Recovery strategies
 */
export enum RecoveryStrategy {
  NONE = 'NONE',
  RETRY = 'RETRY',
  FALLBACK = 'FALLBACK',
  CIRCUIT_BREAKER = 'CIRCUIT_BREAKER',
  DEGRADE_GRACEFULLY = 'DEGRADE_GRACEFULLY'
}

/**
 * Base application error
 */
export class AppError extends Error {
  public readonly code: string;
  public readonly category: ErrorCategory;
  public readonly severity: ErrorSeverity;
  public readonly isOperational: boolean;
  public readonly context?: Record<string, unknown>;
  public readonly timestamp: string;
  public readonly recoveryStrategy: RecoveryStrategy;
  public readonly innerError?: Error;

  constructor(
    message: string,
    code: string,
    category: ErrorCategory,
    severity: ErrorSeverity,
    options?: {
      isOperational?: boolean;
      context?: Record<string, unknown>;
      recoveryStrategy?: RecoveryStrategy;
      innerError?: Error;
    }
  ) {
    super(message);
    this.name = this.constructor.name;
    this.code = code;
    this.category = category;
    this.severity = severity;
    this.isOperational = options?.isOperational ?? true;
    this.context = options?.context;
    this.timestamp = new Date().toISOString();
    this.recoveryStrategy = options?.recoveryStrategy ?? RecoveryStrategy.NONE;
    this.innerError = options?.innerError;

    Error.captureStackTrace(this, this.constructor);
  }

  /**
   * Get user-safe error message (no sensitive info)
   */
  getUserMessage(): string {
    // In production, return generic message for security
    if (process.env.NODE_ENV === 'production' && this.severity === ErrorSeverity.CRITICAL) {
      return 'An unexpected error occurred. Please contact support.';
    }
    return this.message;
  }

  /**
   * Convert to JSON
   */
  toJSON(): object {
    return {
      name: this.name,
      message: this.message,
      code: this.code,
      category: this.category,
      severity: this.severity,
      isOperational: this.isOperational,
      timestamp: this.timestamp,
      context: this.context,
      stack: process.env.NODE_ENV === 'development' ? this.stack : undefined
    };
  }
}

/**
 * Validation errors
 */
export class ValidationError extends AppError {
  constructor(message: string, context?: Record<string, unknown>) {
    super(message, 'ERR_VALIDATION', ErrorCategory.VALIDATION, ErrorSeverity.LOW, {
      isOperational: true,
      context,
      recoveryStrategy: RecoveryStrategy.NONE
    });
  }
}

/**
 * Network errors
 */
export class NetworkError extends AppError {
  constructor(message: string, innerError?: Error, context?: Record<string, unknown>) {
    super(message, 'ERR_NETWORK', ErrorCategory.NETWORK, ErrorSeverity.MEDIUM, {
      isOperational: true,
      context,
      recoveryStrategy: RecoveryStrategy.RETRY,
      innerError
    });
  }
}

/**
 * Timeout errors
 */
export class TimeoutError extends AppError {
  constructor(message: string, context?: Record<string, unknown>) {
    super(message, 'ERR_TIMEOUT', ErrorCategory.TIMEOUT, ErrorSeverity.MEDIUM, {
      isOperational: true,
      context,
      recoveryStrategy: RecoveryStrategy.RETRY
    });
  }
}

/**
 * Security errors
 */
export class SecurityError extends AppError {
  constructor(message: string, code: string, context?: Record<string, unknown>) {
    super(message, code, ErrorCategory.SECURITY, ErrorSeverity.CRITICAL, {
      isOperational: true,
      context,
      recoveryStrategy: RecoveryStrategy.NONE
    });
  }
}

/**
 * Rate limit errors
 */
export class RateLimitError extends AppError {
  public readonly retryAfter?: number;

  constructor(message: string, retryAfter?: number, context?: Record<string, unknown>) {
    super(message, 'ERR_RATE_LIMIT', ErrorCategory.RATE_LIMIT, ErrorSeverity.MEDIUM, {
      isOperational: true,
      context,
      recoveryStrategy: RecoveryStrategy.RETRY
    });
    this.retryAfter = retryAfter;
  }
}

/**
 * Configuration errors
 */
export class ConfigurationError extends AppError {
  constructor(message: string, context?: Record<string, unknown>) {
    super(message, 'ERR_CONFIGURATION', ErrorCategory.CONFIGURATION, ErrorSeverity.HIGH, {
      isOperational: false,
      context,
      recoveryStrategy: RecoveryStrategy.NONE
    });
  }
}

/**
 * Method not found errors (for optional MCP methods)
 */
export class MethodNotFoundError extends AppError {
  constructor(method: string, context?: Record<string, unknown>) {
    super(
      `Method "${method}" not supported by server`,
      'ERR_METHOD_NOT_FOUND',
      ErrorCategory.EXTERNAL,
      ErrorSeverity.LOW,
      {
        isOperational: true,
        context: { method, ...context },
        recoveryStrategy: RecoveryStrategy.NONE
      }
    );
  }
}

/**
 * Internal errors
 */
export class InternalError extends AppError {
  constructor(message: string, innerError?: Error, context?: Record<string, unknown>) {
    super(message, 'ERR_INTERNAL', ErrorCategory.INTERNAL, ErrorSeverity.CRITICAL, {
      isOperational: false,
      context,
      recoveryStrategy: RecoveryStrategy.DEGRADE_GRACEFULLY,
      innerError
    });
  }
}

/**
 * Circuit breaker states
 */
enum CircuitState {
  CLOSED = 'CLOSED',
  OPEN = 'OPEN',
  HALF_OPEN = 'HALF_OPEN'
}

/**
 * Circuit breaker for fault tolerance
 */
export class CircuitBreaker {
  private state: CircuitState = CircuitState.CLOSED;
  private failureCount: number = 0;
  private successCount: number = 0;
  private lastFailureTime?: number;
  private nextAttemptTime?: number;

  constructor(
    private readonly threshold: number = 5,
    private readonly timeout: number = 60000,
    private readonly halfOpenSuccessThreshold: number = 2,
    private readonly name: string = 'default'
  ) { }

  /**
   * Execute operation with circuit breaker
   */
  async execute<T>(operation: () => Promise<T>): Promise<T> {
    if (this.state === CircuitState.OPEN) {
      if (this.nextAttemptTime && Date.now() < this.nextAttemptTime) {
        throw new Error(`Circuit breaker is OPEN for ${this.name}`);
      }
      this.state = CircuitState.HALF_OPEN;
      this.successCount = 0;
    }

    try {
      const result = await operation();
      this.onSuccess();
      return result;
    } catch (error) {
      this.onFailure();
      throw error;
    }
  }

  private onSuccess() {
    this.failureCount = 0;

    if (this.state === CircuitState.HALF_OPEN) {
      this.successCount++;
      if (this.successCount >= this.halfOpenSuccessThreshold) {
        this.state = CircuitState.CLOSED;
        this.successCount = 0;
      }
    }
  }

  private onFailure() {
    this.failureCount++;
    this.lastFailureTime = Date.now();

    if (this.state === CircuitState.HALF_OPEN) {
      this.state = CircuitState.OPEN;
      this.nextAttemptTime = Date.now() + this.timeout;
      return;
    }

    if (this.failureCount >= this.threshold) {
      this.state = CircuitState.OPEN;
      this.nextAttemptTime = Date.now() + this.timeout;
    }
  }

  getState(): CircuitState {
    return this.state;
  }

  reset() {
    this.state = CircuitState.CLOSED;
    this.failureCount = 0;
    this.successCount = 0;
    this.lastFailureTime = undefined;
    this.nextAttemptTime = undefined;
  }
}

/**
 * Retry configuration
 */
export interface RetryConfig {
  maxAttempts: number;
  initialDelay: number;
  maxDelay: number;
  backoffMultiplier: number;
  retryableErrors: ErrorCategory[];
}

/**
 * Default retry configuration
 */
export const DEFAULT_RETRY_CONFIG: RetryConfig = {
  maxAttempts: 3,
  initialDelay: 1000,
  maxDelay: 10000,
  backoffMultiplier: 2,
  retryableErrors: [
    ErrorCategory.NETWORK,
    ErrorCategory.TIMEOUT,
    ErrorCategory.RATE_LIMIT
  ]
};

/**
 * Global error handler
 */
export class ErrorHandler {
  private static instance: ErrorHandler;
  private logger: Logger;
  private circuitBreakers: Map<string, CircuitBreaker> = new Map();

  private constructor() {
    this.logger = Logger.getInstance();
  }

  static getInstance(): ErrorHandler {
    if (!ErrorHandler.instance) {
      ErrorHandler.instance = new ErrorHandler();
    }
    return ErrorHandler.instance;
  }

  /**
   * Handle error with logging and auditing
   */
  handle(error: Error | AppError, component: string = 'Unknown'): void {
    // Convert to AppError if needed
    const appError = error instanceof AppError
      ? error
      : new InternalError('Unexpected error', error);

    // Log error
    this.logger.error(
      appError.message,
      error,
      {
        component,
        metadata: {
          code: appError.code,
          category: appError.category,
          severity: appError.severity,
          context: appError.context
        }
      }
    );

    // Audit critical errors
    if (appError.severity === ErrorSeverity.CRITICAL || appError.category === ErrorCategory.SECURITY) {
      this.logger.audit({
        eventType: AuditEventType.ERROR_OCCURRED,
        severity: appError.severity === ErrorSeverity.CRITICAL ? 'critical' : 'high',
        action: 'error_occurred',
        result: 'failure',
        context: {
          component,
          metadata: {
            errorCode: appError.code,
            errorCategory: appError.category
          }
        },
        details: {
          message: appError.message,
          context: appError.context
        }
      });
    }

    // Handle non-operational errors (programming errors)
    if (!appError.isOperational) {
      this.logger.critical('Non-operational error detected', {
        component,
        metadata: {
          error: appError.toJSON()
        }
      });
    }
  }

  /**
   * Execute with retry logic
   */
  async executeWithRetry<T>(
    operation: () => Promise<T>,
    config: Partial<RetryConfig> = {},
    component: string = 'Unknown'
  ): Promise<T> {
    const retryConfig = { ...DEFAULT_RETRY_CONFIG, ...config };
    let lastError: Error | undefined;
    let delay = retryConfig.initialDelay;

    for (let attempt = 1; attempt <= retryConfig.maxAttempts; attempt++) {
      try {
        return await operation();
      } catch (error) {
        lastError = error as Error;

        // Check if error is retryable
        if (error instanceof AppError) {
          if (!retryConfig.retryableErrors.includes(error.category)) {
            throw error;
          }
        }

        // Log retry attempt
        this.logger.warn(`Retry attempt ${attempt}/${retryConfig.maxAttempts}`, {
          component,
          metadata: {
            attempt,
            maxAttempts: retryConfig.maxAttempts,
            delay,
            error: (error as Error).message
          }
        });

        // Don't sleep on last attempt
        if (attempt < retryConfig.maxAttempts) {
          await this.sleep(delay);
          delay = Math.min(delay * retryConfig.backoffMultiplier, retryConfig.maxDelay);
        }
      }
    }

    // All retries failed
    this.handle(lastError!, component);
    throw lastError;
  }

  /**
   * Execute with circuit breaker
   */
  async executeWithCircuitBreaker<T>(
    operation: () => Promise<T>,
    circuitName: string,
    component: string = 'Unknown'
  ): Promise<T> {
    let circuitBreaker = this.circuitBreakers.get(circuitName);

    if (!circuitBreaker) {
      circuitBreaker = new CircuitBreaker(5, 60000, 2, circuitName);
      this.circuitBreakers.set(circuitName, circuitBreaker);
    }

    try {
      return await circuitBreaker.execute(operation);
    } catch (error) {
      this.logger.warn(`Circuit breaker tripped for ${circuitName}`, {
        component,
        metadata: {
          circuitName,
          state: circuitBreaker.getState()
        }
      });
      throw error;
    }
  }

  /**
   * Get circuit breaker state
   */
  getCircuitBreakerState(circuitName: string): string | undefined {
    return this.circuitBreakers.get(circuitName)?.getState();
  }

  /**
   * Reset circuit breaker
   */
  resetCircuitBreaker(circuitName: string): void {
    this.circuitBreakers.get(circuitName)?.reset();
  }

  /**
   * Wrap async function with error handling
   */
  wrapAsync<T extends unknown[], R>(
    fn: (...args: T) => Promise<R>,
    component: string
  ): (...args: T) => Promise<R> {
    return async (...args: T): Promise<R> => {
      try {
        return await fn(...args);
      } catch (error) {
        this.handle(error as Error, component);
        throw error;
      }
    };
  }

  /**
   * Sleep utility
   */
  private sleep(ms: number): Promise<void> {
    return new Promise(resolve => setTimeout(resolve, ms));
  }
}

/**
 * Decorator for automatic error handling
 */
export function HandleErrors(component: string) {
  return function (
    target: unknown,
    propertyKey: string,
    descriptor: PropertyDescriptor
  ) {
    const originalMethod = descriptor.value;
    const errorHandler = ErrorHandler.getInstance();

    descriptor.value = async function (...args: unknown[]) {
      try {
        return await originalMethod.apply(this, args);
      } catch (error) {
        errorHandler.handle(error as Error, `${component}.${propertyKey}`);
        throw error;
      }
    };

    return descriptor;
  };
}

// Export singleton
export const errorHandler = ErrorHandler.getInstance();
