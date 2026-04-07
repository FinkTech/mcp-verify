# ⚡ Stress Testing Example

## Why Load Test Your MCP Server?

Before deploying to production, you need to know:

- How many concurrent LLM requests can it handle?
- What's the latency under load?
- Where does it start to slow down?
- Will it crash under high concurrency?

## Basic Stress Test

### Start Light

```bash
# 5 concurrent clients for 10 seconds
mcp-verify stress http://localhost:3000
```

### Expected Output

```
⠋ Starting stress test...
⠙ Simulating load: 5 clients for 10s...
✓ Stress test complete!

Performance Report:
──────────────────────────────────────────────────
Total Requests: 127
Success Rate:   100%
Throughput:     12 req/sec
Latency (Avg):  42 ms
Latency (P95):  68 ms
Latency (Max):  95 ms

Latency Distribution:
       30-40 ms ▏ ████████████████████ (45%)
       40-50 ms ▏ ████████████ (30%)
       50-60 ms ▏ ████ (12%)
       60-70 ms ▏ ██ (8%)
       70-80 ms ▏ █ (3%)
       80-90 ms ▏ █ (2%)
──────────────────────────────────────────────────
```

## Interpreting Results

### Throughput

```
12 req/sec = Your server handles 12 requests per second
```

**Good:** > 10 req/sec for simple servers
**Great:** > 50 req/sec
**Excellent:** > 100 req/sec

### Latency P95

```
P95: 68ms = 95% of requests complete in 68ms or less
```

**Good:** < 100ms
**Great:** < 50ms
**Excellent:** < 20ms

### Success Rate

```
100% = No failed requests
```

**Good:** > 99%
**Acceptable:** > 95%
**Bad:** < 95% (investigate errors)

## Heavy Load Test

### Ramp Up Gradually

```bash
# 10 users, 30 seconds
mcp-verify stress http://localhost:3000 --users 10 --duration 30

# 25 users, 60 seconds
mcp-verify stress http://localhost:3000 --users 25 --duration 60

# 50 users, 60 seconds (heavy!)
mcp-verify stress http://localhost:3000 --users 50 --duration 60
```

### Watch for Performance Degradation

```bash
# Light load
Latency (P95): 68 ms   ✅

# Medium load
Latency (P95): 95 ms   ⚠️ Getting slower

# Heavy load
Latency (P95): 1250 ms ❌ Unacceptable
```

## Identifying Bottlenecks

### Scenario 1: High Latency, Low Throughput

```
Throughput:     3 req/sec  ❌ Low
Latency (P95):  800 ms     ❌ High
```

**Likely cause:**

- Slow database queries
- External API calls without timeout
- Inefficient algorithms

**Solution:**

- Add database indexes
- Implement caching
- Use connection pooling
- Profile your code

### Scenario 2: Many Errors Under Load

```
Success Rate: 72%  ❌ Many failures
Errors:
  • Connection timeout (x45)
  • Server unavailable (x23)
```

**Likely cause:**

- Server running out of resources (CPU/RAM)
- Connection pool exhausted
- Rate limiting triggered

**Solution:**

- Increase server resources
- Optimize memory usage
- Add request queuing
- Implement backpressure

### Scenario 3: Slow Tail Latency

```
Latency (Avg):  45 ms   ✅ Good average
Latency (P95):  200 ms  ⚠️ Some slow requests
Latency (Max):  3000 ms ❌ Very slow outliers
```

**Likely cause:**

- Garbage collection pauses
- Cold start on certain operations
- Lock contention

**Solution:**

- Profile GC behavior
- Warm up caches
- Reduce lock scope
- Use async operations

## Real-World Example

### E-commerce MCP Server

#### Initial Test (Before Optimization)

```bash
mcp-verify stress http://localhost:3000 --users 20 --duration 60
```

```
Total Requests: 245
Success Rate:   87%  ❌
Throughput:     4 req/sec  ❌
Latency (P95):  2400 ms  ❌

Errors Encountered:
  • Database connection timeout (x18)
  • Server returned 500 (x14)
```

**Diagnosis:** Database connections exhausted

#### After Adding Connection Pool

```typescript
// Fixed database connection pooling
const pool = new Pool({
  max: 20, // 20 connections
  idleTimeoutMillis: 30000,
  connectionTimeoutMillis: 2000,
});
```

#### After Optimization

```bash
mcp-verify stress http://localhost:3000 --users 20 --duration 60
```

```
Total Requests: 1,847
Success Rate:   99.8%  ✅
Throughput:     31 req/sec  ✅
Latency (P95):  95 ms  ✅
```

**Result:** 8x throughput improvement!

## Advanced: Long Duration Test

### Find Memory Leaks

```bash
# Run for 10 minutes to spot memory leaks
mcp-verify stress http://localhost:3000 --users 10 --duration 600
```

Watch your server's memory usage during the test:

```bash
# In another terminal
while true; do
  ps aux | grep your-server
  sleep 5
done
```

If memory grows continuously → you have a leak

## CI/CD Integration

### Performance Regression Check

```yaml
# .github/workflows/performance.yml
- name: Load Test
  run: |
    mcp-verify stress http://localhost:3000 --users 10 --duration 30 > results.txt

    # Fail if P95 > 100ms
    p95=$(grep "P95:" results.txt | awk '{print $3}')
    if [ $p95 -gt 100 ]; then
      echo "❌ Performance regression: P95 = ${p95}ms (max 100ms)"
      exit 1
    fi
```

## Best Practices

### 1. Test Realistic Scenarios

```bash
# Don't just test initialization
# Test actual tool usage patterns
```

### 2. Warm Up First

```bash
# Run a light test first to warm caches
mcp-verify stress http://localhost:3000 --users 1 --duration 5

# Then run the real test
mcp-verify stress http://localhost:3000 --users 25 --duration 60
```

### 3. Test Different Load Patterns

```bash
# Sustained load
mcp-verify stress http://localhost:3000 --users 10 --duration 120

# Burst traffic
mcp-verify stress http://localhost:3000 --users 50 --duration 10
```

### 4. Monitor Server Resources

Use tools like:

- `htop` - CPU and memory
- `iotop` - Disk I/O
- `netstat` - Network connections
- APM tools - Application metrics

## Troubleshooting Slow Tests

### Test is Hanging?

```bash
# Add verbose flag to see what's happening
mcp-verify stress http://localhost:3000 --users 5 --duration 10 --verbose
```

### Connection Refused?

```bash
# Server might not be running
curl http://localhost:3000

# Or run diagnostics
mcp-verify doctor http://localhost:3000
```

### Results Look Wrong?

```bash
# Make sure server is actually handling requests
tail -f your-server.log
```

## Next Steps

1. Run baseline test (5 users, 10s)
2. Gradually increase load
3. Find breaking point
4. Optimize bottlenecks
5. Re-test
6. Add to CI/CD

## Learn More

- [HTTP Load Testing Best Practices](https://www.nginx.com/blog/load-testing-best-practices/)
- [Performance Testing Guide](https://github.com/FinkTech/mcp-verify/docs/)
