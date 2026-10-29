import test from 'node:test';
import assert from 'node:assert/strict';
import { TraceStore, isValidRunId, newRunId } from '../src/trace.js';
import { fakeJwt } from './helpers.js';

const quiet = () => {};
const evt = (i) => ({ stepId: `x-${i}`, from: 'daemon', to: 'entra', label: `L${i}`, determinism: 'protocol', status: 'ok' });

test('runId validation', () => {
  assert.ok(isValidRunId('abcdEFGH'));
  assert.ok(isValidRunId('a_b-c'.padEnd(64, 'x')));
  for (const bad of ['short', 'a'.repeat(65), 'has space1', 'bad/char1', '../../etc', null, 123, undefined]) {
    assert.equal(isValidRunId(bad), false, String(bad));
  }
});

test('create: server-issued run IDs (128 bits) and read keys (256 bits), all unique', () => {
  const t = new TraceStore({ log: quiet });
  const ids = new Set();
  const keys = new Set();
  for (let i = 0; i < 50; i += 1) {
    const { runId, traceKey } = t.create('obo');
    assert.ok(isValidRunId(runId));
    assert.equal(Buffer.from(runId, 'base64url').length, 16);
    assert.equal(Buffer.from(traceKey, 'base64url').length, 32);
    ids.add(runId);
    keys.add(traceKey);
  }
  assert.equal(ids.size, 50);
  assert.equal(keys.size, 50);
  assert.notEqual(newRunId(), newRunId());
  // Only a hash of the key is stored.
  const { runId, traceKey } = t.create('obo');
  assert.ok(!JSON.stringify([...t.runs.values()].map((r) => ({ ...r, keyHash: r.keyHash.toString('base64url') }))).includes(traceKey));
  assert.ok(t.has(runId));
});

test('read: needs the right key; unknown run and wrong key both return null', () => {
  const t = new TraceStore({ log: quiet });
  const { runId, traceKey } = t.create('obo');
  t.start(runId, 'obo');
  t.add(runId, evt(1));
  assert.equal(t.read(runId, traceKey).events.length, 1);
  assert.equal(t.read(runId, traceKey, 1).events.length, 0);
  const other = t.create('obo');
  for (const key of [undefined, null, '', 'wrong', other.traceKey, `${traceKey}x`, traceKey.slice(1), 'k'.repeat(10_000)]) {
    assert.equal(t.read(runId, key), null, String(key).slice(0, 20));
  }
  assert.equal(t.read('unknown-run-id', traceKey), null);
  assert.equal(t.read('../../etc', traceKey), null);
});

test('start: only reopens an existing run of the same flow', () => {
  const t = new TraceStore({ log: quiet });
  assert.equal(t.start('client-picked-1', 'obo'), null);
  assert.equal(t.has('client-picked-1'), false);
  const { runId } = t.create('obo');
  assert.equal(t.start(runId, 'mcp'), null);
  assert.ok(t.start(runId, 'obo'));
  assert.equal(t.flowOf(runId), 'obo');
  assert.equal(t.flowOf('unknown-run-1'), null);
});

test('add/get with since, seq and required fields', () => {
  const t = new TraceStore({ log: quiet });
  const { runId } = t.create('test');
  t.start(runId, 'test');
  for (let i = 0; i < 5; i += 1) t.add(runId, evt(i));
  const all = t.get(runId);
  assert.equal(all.events.length, 5);
  assert.equal(all.done, false);
  assert.equal(all.error, null);
  all.events.forEach((e, i) => {
    assert.equal(e.seq, i);
    for (const k of ['seq', 'stepId', 'ts', 'status', 'from', 'to', 'label']) assert.ok(k in e, k);
    assert.ok(!Number.isNaN(Date.parse(e.ts)));
  });
  assert.deepEqual(t.get(runId, '3').events.map((e) => e.seq), [3, 4]);
  assert.deepEqual(t.get(runId, 'junk').events.length, 5);
  assert.equal(t.get(runId, 99).events.length, 0);
  t.finish(runId, 'boom');
  assert.deepEqual({ done: t.get(runId).done, error: t.get(runId).error }, { done: true, error: 'boom' });
});

test('unknown run returns empty, not an error', () => {
  const t = new TraceStore({ log: quiet });
  assert.deepEqual(t.get('unknown-run'), { events: [], done: false, error: null });
  assert.equal(t.add('unknown-run', evt(1)), null);
});

test('events are capped at 500 per run', () => {
  const t = new TraceStore({ log: quiet });
  const { runId } = t.create('cap');
  for (let i = 0; i < 600; i += 1) t.add(runId, evt(i));
  const r = t.get(runId);
  assert.equal(r.events.length, 500);
  assert.equal(r.events[499].seq, 499);
  assert.equal(r.truncated, true);
});

test('bytes are capped per run', () => {
  const t = new TraceStore({ log: quiet, maxRunBytes: 5000 });
  const { runId } = t.create('cap');
  for (let i = 0; i < 50; i += 1) t.add(runId, { ...evt(i), note: 'n'.repeat(400) });
  const r = t.get(runId);
  assert.ok(r.events.length < 50 && r.events.length > 0);
  assert.ok(JSON.stringify(r.events).length <= 5000);
  assert.equal(r.truncated, true);
});

test('stored runs are capped: finished runs are evicted before running ones', () => {
  const t = new TraceStore({ log: quiet, maxRuns: 3 });
  const a = t.create('x');
  t.start(a.runId, 'x').running = true;
  const b = t.create('x');
  const c = t.create('x');
  const d = t.create('x');
  assert.equal(t.runs.size, 3);
  assert.ok(t.has(a.runId), 'running run kept');
  assert.equal(t.has(b.runId), false, 'oldest idle run evicted');
  assert.ok(t.has(c.runId) && t.has(d.runId));
  assert.equal(t.runningCount(), 1);
  for (let i = 0; i < 20; i += 1) t.create('x');
  assert.equal(t.runs.size, 3);
});

test('runs expire after 30 minutes', () => {
  let now = 1_000_000;
  const t = new TraceStore({ log: quiet, now: () => now });
  const { runId, traceKey } = t.create('old');
  t.add(runId, evt(1));
  now += 29 * 60 * 1000;
  assert.equal(t.read(runId, traceKey).events.length, 1);
  now += 2 * 60 * 1000;
  assert.equal(t.read(runId, traceKey), null);
  assert.equal(t.runs.size, 0);
});

test('store scrubs full tokens and secrets that slip into events', () => {
  const lines = [];
  const t = new TraceStore({ log: (l) => lines.push(l), secrets: ['my-secret-123'] });
  const { runId } = t.create('x');
  const at = fakeJwt({ x: 1 });
  t.add(runId, { ...evt(1), note: `oops ${at.raw} my-secret-123`, data: { t: at.raw } });
  t.finish(runId, 'error with my-secret-123');
  const s = JSON.stringify(t.get(runId));
  assert.ok(!s.includes(at.signature));
  assert.ok(!s.includes('my-secret-123'));
  assert.deepEqual(lines, ['flow x step x-1 ok']);
});
