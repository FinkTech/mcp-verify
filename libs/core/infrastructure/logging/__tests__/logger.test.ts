/**
 * Copyright (c) 2026 FinkTech
 *
 * This file is part of MCP Verify.
 * Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
 * See LICENSE file in the project root for full license information.
 */
/**
 * Logger Tests
 * Comprehensive test suite for enterprise logging system
 */

import {
  Logger,
  LogLevel,
  AuditEventType,
  createScopedLogger,
  PerformanceTimer,
} from '../logger';

describe('Logger', () => {
  let logger: Logger;

  beforeEach(() => {
    // Reset singleton for each test
    (Logger as any).instance = undefined;
    logger = Logger.getInstance();
    logger.clearLogs();
    logger.clearAudit();
  });

  describe('Singleton Pattern', () => {
    it('should return the same instance', () => {
      const instance1 = Logger.getInstance();
      const instance2 = Logger.getInstance();
      expect(instance1).toBe(instance2);
    });

    it('should accept configuration on first instantiation', () => {
      (Logger as any).instance = undefined;
      const logger = Logger.getInstance({ minLevel: LogLevel.WARN });
      logger.debug('test');
      expect(logger.getLogs().length).toBe(0);
    });
  });

  describe('Log Levels', () => {
    it('should log debug messages when level is DEBUG', () => {
      logger.configure({ minLevel: LogLevel.DEBUG });
      logger.debug('debug message');
      const logs = logger.getLogs();
      expect(logs.length).toBe(1);
      expect(logs[0].level).toBe(LogLevel.DEBUG);
      expect(logs[0].message).toBe('debug message');
    });

    it('should log info messages', () => {
      logger.info('info message');
      const logs = logger.getLogs();
      expect(logs.length).toBe(1);
      expect(logs[0].level).toBe(LogLevel.INFO);
    });

    it('should log warning messages', () => {
      logger.warn('warning message');
      const logs = logger.getLogs();
      expect(logs.length).toBe(1);
      expect(logs[0].level).toBe(LogLevel.WARN);
    });

    it('should log error messages with error object', () => {
      const error = new Error('test error');
      logger.error('error message', error);
      const logs = logger.getLogs();
      expect(logs.length).toBe(1);
      expect(logs[0].level).toBe(LogLevel.ERROR);
      expect(logs[0].error?.message).toBe('test error');
    });

    it('should log critical messages', () => {
      logger.critical('critical message');
      const logs = logger.getLogs();
      // Critical creates 2 logs: one from log() and one from audit()
      expect(logs.length).toBe(2);
      expect(logs[0].level).toBe(LogLevel.CRITICAL);
    });

    it('should filter logs below minimum level', () => {
      logger.configure({ minLevel: LogLevel.WARN });
      logger.debug('debug');
      logger.info('info');
      logger.warn('warn');
      const logs = logger.getLogs();
      expect(logs.length).toBe(1);
      expect(logs[0].message).toBe('warn');
    });
  });

  describe('PII Redaction', () => {
    it('should redact SSN', () => {
      logger.info('SSN: 123-45-6789');
      const logs = logger.getLogs();
      expect(logs[0].message).toContain('***-**-****');
      expect(logs[0].message).not.toContain('123-45-6789');
    });

    it('should redact credit card numbers', () => {
      logger.info('Card: 4532-1234-5678-9010');
      const logs = logger.getLogs();
      expect(logs[0].message).toContain('****-****-****-****');
      expect(logs[0].message).not.toContain('4532');
    });

    it('should redact email addresses', () => {
      logger.info('Email: user@example.com');
      const logs = logger.getLogs();
      expect(logs[0].message).toContain('***@***.***');
      expect(logs[0].message).not.toContain('user@example.com');
    });

    it('should redact phone numbers', () => {
      logger.info('Phone: 555-123-4567');
      const logs = logger.getLogs();
      expect(logs[0].message).toContain('***-***-****');
    });

    it('should redact API tokens', () => {
      logger.info('Token: Bearer abc123def456');
      const logs = logger.getLogs();
      expect(logs[0].message).toContain('Bearer ***REDACTED***');
      expect(logs[0].message).not.toContain('abc123def456');
    });

    it('should allow disabling PII redaction', () => {
      logger.configure({ redactPII: false });
      logger.info('SSN: 123-45-6789');
      const logs = logger.getLogs();
      expect(logs[0].message).toContain('123-45-6789');
    });
  });

  describe('Context', () => {
    it('should include context in log entries', () => {
      logger.info('test', { component: 'TestComponent', userId: '123' });
      const logs = logger.getLogs();
      expect(logs[0].context.component).toBe('TestComponent');
      expect(logs[0].context.userId).toBe('123');
    });

    it('should include metadata in context', () => {
      logger.info('test', { metadata: { key: 'value' } });
      const logs = logger.getLogs();
      expect(logs[0].context.metadata).toEqual({ key: 'value' });
    });

    it('should include correlation ID', () => {
      logger.info('test', { correlationId: 'abc-123' });
      const logs = logger.getLogs();
      expect(logs[0].context.correlationId).toBe('abc-123');
    });
  });

  describe('Audit Logging', () => {
    it('should log audit events', () => {
      logger.audit({
        eventType: AuditEventType.SECURITY_FINDING,
        severity: 'high',
        action: 'test_action',
        result: 'success',
        context: {},
      });
      const audit = logger.getAuditTrail();
      expect(audit.length).toBe(1);
      expect(audit[0].eventType).toBe(AuditEventType.SECURITY_FINDING);
    });

    it('should include timestamp in audit entries', () => {
      logger.audit({
        eventType: AuditEventType.VALIDATION_STARTED,
        severity: 'low',
        action: 'validation',
        result: 'success',
        context: {},
      });
      const audit = logger.getAuditTrail();
      expect(audit[0].timestamp).toBeDefined();
      expect(new Date(audit[0].timestamp).getTime()).toBeGreaterThan(0);
    });

    it('should also create regular log entry for audit', () => {
      logger.audit({
        eventType: AuditEventType.SECURITY_CRITICAL,
        severity: 'critical',
        action: 'critical_event',
        result: 'failure',
        context: {},
      });
      const logs = logger.getLogs();
      expect(logs.length).toBeGreaterThan(0);
      expect(logs[0].message).toContain('[AUDIT]');
    });

    it('should filter audit by event type', () => {
      logger.audit({
        eventType: AuditEventType.VALIDATION_STARTED,
        severity: 'low',
        action: 'test1',
        result: 'success',
        context: {},
      });
      logger.audit({
        eventType: AuditEventType.SECURITY_FINDING,
        severity: 'high',
        action: 'test2',
        result: 'success',
        context: {},
      });
      const filtered = logger.getAuditByEventType(AuditEventType.SECURITY_FINDING);
      expect(filtered.length).toBe(1);
      expect(filtered[0].action).toBe('test2');
    });

    it('should trim audit log when exceeding max size', () => {
      for (let i = 0; i < 10001; i++) {
        logger.audit({
          eventType: AuditEventType.VALIDATION_STARTED,
          severity: 'low',
          action: `test${i}`,
          result: 'success',
          context: {},
        });
      }
      const audit = logger.getAuditTrail();
      expect(audit.length).toBeLessThanOrEqual(5000);
    });
  });

  describe('Configuration', () => {
    it('should allow runtime configuration changes', () => {
      logger.configure({ minLevel: LogLevel.ERROR });
      logger.info('info message');
      logger.error('error message');
      const logs = logger.getLogs();
      expect(logs.length).toBe(1);
      expect(logs[0].message).toBe('error message');
    });

    it('should allow disabling console output', () => {
      logger.configure({ enableConsole: false });
      logger.info('test');
      // Just verify it doesn't throw
      expect(logger.getLogs().length).toBe(1);
    });

    it('should allow configuring max message length', () => {
      logger.configure({ maxMessageLength: 10 });
      logger.info('This is a very long message that should be truncated');
      const logs = logger.getLogs();
      expect(logs[0].message.length).toBeLessThanOrEqual(40); // With truncation suffix
    });
  });

  describe('Log Retrieval', () => {
    beforeEach(() => {
      logger.info('info1');
      logger.warn('warn1');
      logger.error('error1');
    });

    it('should retrieve all logs', () => {
      const logs = logger.getLogs();
      expect(logs.length).toBe(3);
    });

    it('should retrieve limited number of logs', () => {
      const logs = logger.getLogs(2);
      expect(logs.length).toBe(2);
    });

    it('should retrieve logs by level', () => {
      const errorLogs = logger.getLogsByLevel(LogLevel.ERROR);
      expect(errorLogs.length).toBe(1);
      expect(errorLogs[0].message).toBe('error1');
    });

    it('should retrieve logs above certain level', () => {
      const warningAndAbove = logger.getLogsByLevel(LogLevel.WARN);
      expect(warningAndAbove.length).toBe(2);
    });
  });

  describe('Statistics', () => {
    beforeEach(() => {
      logger.info('info1');
      logger.warn('warn1');
      logger.error('error1');
      logger.audit({
        eventType: AuditEventType.SECURITY_FINDING,
        severity: 'high',
        action: 'test',
        result: 'success',
        context: {},
      });
    });

    it('should provide statistics', () => {
      const stats = logger.getStats();
      expect(stats.totalLogs).toBe(4); // 3 logs + 1 from audit
      expect(stats.totalAudit).toBe(1);
    });

    it('should count logs by level', () => {
      const stats = logger.getStats();
      expect(stats.byLevel['INFO']).toBe(1);
      expect(stats.byLevel['WARN']).toBe(1);
      // 2 ERROR logs: one from error() and one from audit()
      expect(stats.byLevel['ERROR']).toBe(2);
    });

    it('should count audit events by type', () => {
      const stats = logger.getStats();
      expect(stats.byEventType[AuditEventType.SECURITY_FINDING]).toBe(1);
    });
  });

  describe('Export', () => {
    it('should export logs as JSON', () => {
      logger.info('test1');
      logger.info('test2');
      const exported = logger.exportLogs();
      const parsed = JSON.parse(exported);
      expect(parsed.logs).toBeDefined();
      expect(parsed.audit).toBeDefined();
      expect(parsed.exportedAt).toBeDefined();
      expect(parsed.logs.length).toBe(2);
    });
  });

  describe('Clear', () => {
    it('should clear logs', () => {
      logger.info('test');
      logger.clearLogs();
      expect(logger.getLogs().length).toBe(0);
    });

    it('should clear audit trail', () => {
      logger.audit({
        eventType: AuditEventType.VALIDATION_STARTED,
        severity: 'low',
        action: 'test',
        result: 'success',
        context: {},
      });
      logger.clearAudit();
      expect(logger.getAuditTrail().length).toBe(0);
    });
  });
});

describe('Scoped Logger', () => {
  beforeEach(() => {
    (Logger as any).instance = undefined;
    const logger = Logger.getInstance();
    logger.clearLogs();
  });

  it('should create scoped logger with component context', () => {
    const scopedLogger = createScopedLogger('TestComponent');
    scopedLogger.info('test message');

    const logger = Logger.getInstance();
    const logs = logger.getLogs();
    expect(logs[0].context.component).toBe('TestComponent');
  });

  it('should merge default context with call context', () => {
    const scopedLogger = createScopedLogger('TestComponent', { userId: '123' });
    scopedLogger.info('test', { operation: 'test_op' });

    const logger = Logger.getInstance();
    const logs = logger.getLogs();
    expect(logs[0].context.component).toBe('TestComponent');
    expect(logs[0].context.userId).toBe('123');
    expect(logs[0].context.operation).toBe('test_op');
  });

  it('should support all log levels', () => {
    const scopedLogger = createScopedLogger('TestComponent');
    scopedLogger.debug('debug');
    scopedLogger.info('info');
    scopedLogger.warn('warn');
    scopedLogger.error('error', new Error('test'));
    scopedLogger.critical('critical');

    const logger = Logger.getInstance();
    const logs = logger.getLogs();
    expect(logs.length).toBeGreaterThan(0);
  });
});

describe('Performance Timer', () => {
  beforeEach(() => {
    (Logger as any).instance = undefined;
    const logger = Logger.getInstance();
    logger.clearLogs();
  });

  it('should measure operation duration', () => {
    const timer = new PerformanceTimer('test_operation', 'TestComponent');
    const duration = timer.end();

    expect(duration).toBeGreaterThanOrEqual(0);

    const logger = Logger.getInstance();
    const logs = logger.getLogs();
    expect(logs.length).toBe(1);
    expect(logs[0].message).toContain('test_operation completed');
    expect(logs[0].context.duration).toBeDefined();
  });

  it('should log duration in context', () => {
    const timer = new PerformanceTimer('test_operation', 'TestComponent');
    timer.end();

    const logger = Logger.getInstance();
    const logs = logger.getLogs();
    expect(logs[0].context.duration).toBeGreaterThanOrEqual(0);
  });

  it('should handle errors with endWithError', () => {
    const timer = new PerformanceTimer('test_operation', 'TestComponent');
    const error = new Error('test error');
    const duration = timer.endWithError(error);

    expect(duration).toBeGreaterThanOrEqual(0);

    const logger = Logger.getInstance();
    const logs = logger.getLogs();
    expect(logs.length).toBe(1);
    expect(logs[0].message).toContain('test_operation failed');
  });

  it('should include additional context', () => {
    const timer = new PerformanceTimer('test_operation', 'TestComponent');
    timer.end({ userId: '123' });

    const logger = Logger.getInstance();
    const logs = logger.getLogs();
    expect(logs[0].context.userId).toBe('123');
  });
});
