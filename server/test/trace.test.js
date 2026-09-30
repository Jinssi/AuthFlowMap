import test from 'node:test';
import assert from 'node:assert/strict';
import { TraceStore, isValidRunId } from '../src/trace.js';
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

test('add/get with since, seq and required fields', () => {
  const t = new TraceStore({ log: quiet });
  t.start('run-00001', 'test');
  for (let i = 0; i < 5; i += 1) t.add('run-00001', evt(i));
  const all = t.get('run-00001');
  assert.equal(all.events.length, 5);
  assert.equal(all.done, false);
  assert.equal(all.error, null);
  all.events.forEach((e, i) => {
    assert.equal(e.seq, i);
    for (const k of ['seq', 'stepId', 'ts', 'status', 'from', 'to', 'label']) assert.ok(k in e, k);
    assert.ok(!Number.isNaN(Date.parse(e.ts)));
  });
  assert.deepEqual(t.get('run-00001', '3').events.map((e) => e.seq), [3, 4]);
  assert.deepEqual(t.get('run-00001', 'junk').events.length, 5);
  assert.equal(t.get('run-00001', 99).events.length, 0);
  t.finish('run-00001', 'boom');
  assert.deepEqual({ done: t.get('run-00001').done, error: t.get('run-00001').error }, { done: true, error: 'boom' });
});

test('unknown run returns empty, not an error', () => {
  const t = new TraceStore({ log: quiet });
  assert.deepEqual(t.get('unknown-run'), { events: [], done: false, error: null });
  assert.equal(t.add('unknown-run', evt(1)), null);
});

test('events are capped at 500 per run', () => {
  const t = new TraceStore({ log: quiet });
  t.start('cap-run-1');
  for (let i = 0; i < 600; i += 1) t.add('cap-run-1', evt(i));
  const r = t.get('cap-run-1');
  assert.equal(r.events.length, 500);
  assert.equal(r.events[499].seq, 499);
});

test('runs expire after 30 minutes', () => {
  let now = 1_000_000;
  const t = new TraceStore({ log: quiet, now: () => now });
  t.start('old-run-1');
  t.add('old-run-1', evt(1));
  now += 29 * 60 * 1000;
  assert.equal(t.get('old-run-1').events.length, 1);
  now += 2 * 60 * 1000;
  assert.equal(t.get('old-run-1').events.length, 0);
  assert.equal(t.runs.size, 0);
});

test('store scrubs full tokens and secrets that slip into events', () => {
  const lines = [];
  const t = new TraceStore({ log: (l) => lines.push(l), secrets: ['my-secret-123'] });
  t.start('scrub-run');
  const at = fakeJwt({ x: 1 });
  t.add('scrub-run', { ...evt(1), note: `oops ${at.raw} my-secret-123`, data: { t: at.raw } });
  t.finish('scrub-run', 'error with my-secret-123');
  const s = JSON.stringify(t.get('scrub-run'));
  assert.ok(!s.includes(at.signature));
  assert.ok(!s.includes('my-secret-123'));
  assert.deepEqual(lines, ['flow x step x-1 ok']);
});
