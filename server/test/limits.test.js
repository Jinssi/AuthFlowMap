// Rate limits and caps on run starts and stored traces.
import test from 'node:test';
import assert from 'node:assert/strict';
import { createApp } from '../src/server.js';
import { buildConfig } from '../src/config.js';
import { RateLimiter } from '../src/limits.js';
import { TraceStore } from '../src/trace.js';
import { listen, jsonResponse, waitDone, TEST_ENV } from './helpers.js';

const cfg = buildConfig(TEST_ENV);
const post = (base, p, body) => fetch(`${base}${p}`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(body) });

test('RateLimiter: sliding window with Retry-After seconds', () => {
  let now = 0;
  const rl = new RateLimiter({ max: 3, windowMs: 60_000, now: () => now });
  assert.deepEqual([rl.take(), rl.take(), rl.take()], [0, 0, 0]);
  assert.equal(rl.take(), 60);
  now = 30_000;
  assert.equal(rl.take(), 30);
  now = 60_001;
  assert.equal(rl.take(), 0, 'the first hits left the window');
  assert.equal(rl.hits.length, 1, 'rejected attempts are not counted');
});

test('POST /api/runs: only browser flows, capped per minute with 429 + Retry-After', async () => {
  const app = createApp({ cfg, log: () => {}, limits: { runsPerMinute: 3 } });
  const s = await listen(app);
  try {
    for (const flow of [undefined, 'client-credentials', 'ca-sim', '__proto__', 'x'.repeat(100), 42]) {
      assert.equal((await post(s.base, '/api/runs', { flow })).status, 400, String(flow));
    }
    const ok = [];
    for (const flow of ['obo', 'mcp', 'web-app']) {
      const res = await post(s.base, '/api/runs', { flow, runId: 'client-picked-1' });
      assert.equal(res.status, 201);
      ok.push(await res.json());
    }
    assert.equal(app.locals.ctx.trace.has('client-picked-1'), false);
    const res = await post(s.base, '/api/runs', { flow: 'obo' });
    assert.equal(res.status, 429);
    assert.ok(Number(res.headers.get('retry-after')) >= 1);
    assert.equal((await res.json()).error, 'too_many_requests');
    // Server flows share the same per-minute budget.
    const live = await post(s.base, '/api/live/device-code', {});
    assert.equal(live.status, 429);
    assert.ok(Number(live.headers.get('retry-after')) >= 1);
    // Reading traces is not rate limited.
    for (const r of ok) assert.equal((await fetch(`${s.base}/api/trace/${r.runId}`, { headers: { 'x-trace-key': r.traceKey } })).status, 200);
  } finally {
    await s.close();
  }
});

test('server flows: at most N running at once (429 + Retry-After), slots free when runs finish', async () => {
  let release;
  const gate = new Promise((r) => { release = r; });
  const fetchImpl = async (url) => {
    if (String(url).endsWith('/oauth2/v2.0/token')) {
      await gate;
      return jsonResponse(401, { error: 'invalid_client', error_description: 'test' });
    }
    return jsonResponse(404, {});
  };
  const app = createApp({ cfg, fetchImpl, log: () => {}, limits: { maxConcurrentFlows: 2, runsPerMinute: 100 } });
  const s = await listen(app);
  try {
    const a = await post(s.base, '/api/live/client-credentials', { variant: 'secret' });
    const b = await post(s.base, '/api/live/agent-autonomous', {});
    assert.deepEqual([a.status, b.status], [202, 202]);
    const ids = [(await a.json()).runId, (await b.json()).runId];
    assert.equal(app.locals.ctx.trace.runningCount(), 2);

    const c = await post(s.base, '/api/live/client-credentials', { variant: 'secret' });
    assert.equal(c.status, 429);
    assert.equal(c.headers.get('retry-after'), '5');
    assert.match((await c.json()).error_description, /At most 2 server flows/);
    // Browser flow runs are not "running" server flows, so they are still allowed.
    assert.equal((await post(s.base, '/api/runs', { flow: 'obo' })).status, 201);

    release();
    for (const id of ids) await waitDone(app.locals.ctx.trace, id);
    assert.equal(app.locals.ctx.trace.runningCount(), 0);
    const d = await post(s.base, '/api/live/client-credentials', { variant: 'secret' });
    assert.equal(d.status, 202);
    await waitDone(app.locals.ctx.trace, (await d.json()).runId);
  } finally {
    await s.close();
  }
});

test('stored traces are capped in count even under many run starts', async () => {
  const trace = new TraceStore({ log: () => {}, maxRuns: 5 });
  const app = createApp({ cfg, trace, log: () => {}, limits: { runsPerMinute: 1000 } });
  const s = await listen(app);
  try {
    let last;
    for (let i = 0; i < 40; i += 1) {
      const res = await post(s.base, '/api/runs', { flow: 'obo' });
      assert.equal(res.status, 201);
      last = await res.json();
    }
    assert.equal(trace.runs.size, 5);
    assert.equal((await fetch(`${s.base}/api/trace/${last.runId}`, { headers: { 'x-trace-key': last.traceKey } })).status, 200);
  } finally {
    await s.close();
  }
});

test('default limits: 4 concurrent server flows, 30 run starts per minute', async () => {
  const { DEFAULT_LIMITS } = await import('../src/limits.js');
  assert.equal(DEFAULT_LIMITS.maxConcurrentFlows, 4);
  assert.equal(DEFAULT_LIMITS.runsPerMinute, 30);
  const t = new TraceStore();
  assert.equal(t.maxRuns, 100);
  assert.equal(t.ttlMs, 30 * 60 * 1000);
});
