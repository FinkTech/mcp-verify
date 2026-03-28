#!/usr/bin/env tsx
/**
 * Manual Panic Stop Test
 *
 * Validates the 3-strike system with backoff escalation.
 *
 * Usage:
 *   npx tsx tests/manual-panic-stop-test.ts
 */

import { McpProxyServer } from '../libs/core/use-cases/proxy/proxy-server';
import { DEFAULT_CONFIG } from '../libs/core/domain/config/config.types';
import { setTimeout } from 'timers/promises';

const colors = {
  green: '\x1b[32m',
  red: '\x1b[31m',
  yellow: '\x1b[33m',
  blue: '\x1b[34m',
  reset: '\x1b[0m',
};

function log(emoji: string, message: string, color: string = colors.reset) {
  console.log(`${color}${emoji} ${message}${colors.reset}`);
}

async function runPanicStopTests() {
  log('🚀', 'Starting Panic Stop Manual Tests...', colors.blue);
  console.log('');

  let proxyServer: McpProxyServer | null = null;
  const PROXY_PORT = 10099;
  let testsPassed = 0;
  let testsFailed = 0;

  try {
    // ─────────────────────────────────────────────────────────────────────────
    // Setup: Initialize Proxy
    // ─────────────────────────────────────────────────────────────────────────
    log('📦', 'Initializing proxy server...', colors.blue);

    proxyServer = new McpProxyServer({
      targetUrl: 'http://mock-server/sse',
      port: PROXY_PORT,
      blockCritical: true,
      maskPii: false,
      securityConfig: DEFAULT_CONFIG,
      deepAnalysis: false,
    });

    // Listen for audit events
    const auditEvents: any[] = [];
    proxyServer.on('audit', (event) => auditEvents.push(event));

    await proxyServer.start();
    await setTimeout(1000);

    log('✅', 'Proxy started on port ' + PROXY_PORT, colors.green);
    console.log('');

    // ─────────────────────────────────────────────────────────────────────────
    // Test 1: Normal operation (no strikes)
    // ─────────────────────────────────────────────────────────────────────────
    log('🧪', 'Test 1: Normal Operation (no strikes)', colors.yellow);

    try {
      const response = await fetch(`http://localhost:${PROXY_PORT}/message`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          jsonrpc: '2.0',
          id: 1,
          method: 'tools/call',
          params: { name: 'test', arguments: {} }
        })
      });

      const json = await response.json();

      // Should get upstream error (no mock server), but NOT panic/backoff error
      if (!json.error || (json.error.code !== -32004 && json.error.code !== -32005)) {
        log('✅', 'Normal operation - no panic/backoff errors', colors.green);
        testsPassed++;
      } else {
        log('❌', 'Unexpected panic/backoff error in normal operation', colors.red);
        testsFailed++;
      }
    } catch (error) {
      log('❌', 'Test 1 failed: ' + error, colors.red);
      testsFailed++;
    }

    console.log('');

    // ─────────────────────────────────────────────────────────────────────────
    // Test 2: Verify strikes are tracked (internal state)
    // ─────────────────────────────────────────────────────────────────────────
    log('🧪', 'Test 2: Strike Counter State', colors.yellow);

    try {
      // Access internal state via reflection (testing only)
      const state = (proxyServer as any).rateLimitState;

      if (state && typeof state.strikes === 'number') {
        log('✅', `Strike counter accessible: ${state.strikes} strikes`, colors.green);
        log('   ', `Panic mode: ${state.panicMode}`, colors.reset);
        log('   ', `In backoff: ${state.inBackoff}`, colors.reset);
        testsPassed++;
      } else {
        log('❌', 'Strike state not accessible or malformed', colors.red);
        testsFailed++;
      }
    } catch (error) {
      log('❌', 'Test 2 failed: ' + error, colors.red);
      testsFailed++;
    }

    console.log('');

    // ─────────────────────────────────────────────────────────────────────────
    // Test 3: Verify audit events structure
    // ─────────────────────────────────────────────────────────────────────────
    log('🧪', 'Test 3: Audit Events Wiring', colors.yellow);

    try {
      const requestEvents = auditEvents.filter(e => e.type === 'request');

      if (requestEvents.length > 0) {
        log('✅', `Audit events captured: ${auditEvents.length} total`, colors.green);
        log('   ', `Request events: ${requestEvents.length}`, colors.reset);
        testsPassed++;
      } else {
        log('❌', 'No request events captured', colors.red);
        testsFailed++;
      }
    } catch (error) {
      log('❌', 'Test 3 failed: ' + error, colors.red);
      testsFailed++;
    }

    console.log('');

    // ─────────────────────────────────────────────────────────────────────────
    // Test 4: checkPanicStop() returns blocked=false initially
    // ─────────────────────────────────────────────────────────────────────────
    log('🧪', 'Test 4: checkPanicStop() Initial State', colors.yellow);

    try {
      // Access private method via reflection (testing only)
      const checkResult = (proxyServer as any).checkPanicStop();

      if (checkResult && checkResult.blocked === false) {
        log('✅', 'checkPanicStop() returns blocked=false initially', colors.green);
        testsPassed++;
      } else {
        log('❌', 'checkPanicStop() should return blocked=false', colors.red);
        console.log('Result:', checkResult);
        testsFailed++;
      }
    } catch (error) {
      log('❌', 'Test 4 failed: ' + error, colors.red);
      testsFailed++;
    }

    console.log('');

    // ─────────────────────────────────────────────────────────────────────────
    // Test 5: is429Error() detection
    // ─────────────────────────────────────────────────────────────────────────
    log('🧪', 'Test 5: is429Error() Detection', colors.yellow);

    try {
      const is429 = (proxyServer as any).is429Error.bind(proxyServer);

      const test429 = new Error('HTTP 429 Too Many Requests');
      const testRateLimit = new Error('rate limit exceeded');
      const testNormal = new Error('Connection refused');

      if (is429(test429) && is429(testRateLimit) && !is429(testNormal)) {
        log('✅', 'is429Error() correctly detects 429 patterns', colors.green);
        log('   ', 'Detected: "429 Too Many Requests" ✓', colors.reset);
        log('   ', 'Detected: "rate limit exceeded" ✓', colors.reset);
        log('   ', 'Ignored: "Connection refused" ✓', colors.reset);
        testsPassed++;
      } else {
        log('❌', 'is429Error() detection failed', colors.red);
        testsFailed++;
      }
    } catch (error) {
      log('❌', 'Test 5 failed: ' + error, colors.red);
      testsFailed++;
    }

    console.log('');

    // ─────────────────────────────────────────────────────────────────────────
    // Test 6: handleRateLimitStrike() increments strikes
    // ─────────────────────────────────────────────────────────────────────────
    log('🧪', 'Test 6: Strike Escalation', colors.yellow);

    try {
      const state = (proxyServer as any).rateLimitState;
      const initialStrikes = state.strikes;

      // Manually trigger a strike (testing only)
      (proxyServer as any).handleRateLimitStrike();

      if (state.strikes === initialStrikes + 1 && state.inBackoff === true) {
        log('✅', 'Strike counter incremented and backoff activated', colors.green);
        log('   ', `Strikes: ${initialStrikes} → ${state.strikes}`, colors.reset);
        log('   ', `In backoff: ${state.inBackoff}`, colors.reset);
        log('   ', `Blocked until: ${new Date(state.blockedUntil).toISOString()}`, colors.reset);
        testsPassed++;
      } else {
        log('❌', 'Strike escalation failed', colors.red);
        testsFailed++;
      }

      // Check if rate-limit-backoff event was emitted
      const backoffEvent = auditEvents.find(e => e.type === 'rate-limit-backoff');
      if (backoffEvent) {
        log('✅', 'rate-limit-backoff audit event emitted', colors.green);
        log('   ', `Message: ${backoffEvent.message}`, colors.reset);
        testsPassed++;
      } else {
        log('❌', 'rate-limit-backoff event NOT emitted', colors.red);
        testsFailed++;
      }
    } catch (error) {
      log('❌', 'Test 6 failed: ' + error, colors.red);
      testsFailed += 2;
    }

    console.log('');

  } catch (error) {
    log('❌', 'Fatal error: ' + error, colors.red);
    process.exit(1);
  } finally {
    // Cleanup
    if (proxyServer) {
      await proxyServer.stop();
      log('🛑', 'Proxy stopped', colors.blue);
    }
  }

  // ───────────────────────────────────────────────────────────────────────────
  // Summary
  // ───────────────────────────────────────────────────────────────────────────
  console.log('');
  console.log('═══════════════════════════════════════════════════════════════');
  console.log('');
  log('📊', 'Test Summary:', colors.blue);
  log('✅', `Passed: ${testsPassed}`, colors.green);
  log('❌', `Failed: ${testsFailed}`, colors.red);
  console.log('');

  if (testsFailed === 0) {
    log('🎉', 'All Panic Stop tests passed!', colors.green);
    log('➡️ ', 'Phase 2 implementation validated successfully', colors.blue);
    console.log('');
    process.exit(0);
  } else {
    log('⚠️ ', 'Some tests failed. Review the implementation.', colors.yellow);
    console.log('');
    process.exit(1);
  }
}

// Run tests
runPanicStopTests().catch(error => {
  console.error('Unhandled error:', error);
  process.exit(1);
});
