// In-memory run event store: the contract with the frontend.
// Run IDs and trace read keys are generated here. Clients never choose them.
import crypto from 'node:crypto';
import { scrubDeep } from './mask.js';

export const RUN_ID_RE = /^[A-Za-z0-9_-]{8,64}$/;
export const ACTORS = new Set([
  'user', 'browser', 'api', 'daemon', 'device', 'entra', 'graph', 'agent', 'mcpclient', 'mcpserver', 'llm', 'webapp',
]);
const DETERMINISM = new Set(['protocol', 'ai', 'human', 'policy']);
const STATUS = new Set(['ok', 'error', 'pending']);
const OPTIONAL_FIELDS = ['request', 'response', 'tokens', 'checks', 'note', 'data'];
const MAX_KEY_LENGTH = 256;

export function isValidRunId(runId) {
  return typeof runId === 'string' && RUN_ID_RE.test(runId);
}

/** 128 random bits, base64url (22 chars). */
export function newRunId() {
  return crypto.randomBytes(16).toString('base64url');
}

function keyDigest(key) {
  return crypto.createHash('sha256').update(String(key)).digest();
}

function defaultLog(line) {
  console.log(line);
}

export class TraceStore {
  constructor({
    ttlMs = 30 * 60 * 1000,
    maxEvents = 500,
    maxRuns = 100,
    maxRunBytes = 1_000_000,
    now = () => Date.now(),
    secrets = [],
    log = defaultLog,
  } = {}) {
    this.ttlMs = ttlMs;
    this.maxEvents = maxEvents;
    this.maxRuns = maxRuns;
    this.maxRunBytes = maxRunBytes;
    this.now = now;
    this.secrets = secrets;
    this.log = log;
    this.runs = new Map();
  }

  sweep() {
    const cutoff = this.now() - this.ttlMs;
    for (const [id, run] of this.runs) {
      if (run.createdAt < cutoff) this.runs.delete(id);
    }
  }

  _getLive(runId) {
    if (typeof runId !== 'string') return undefined;
    const run = this.runs.get(runId);
    if (run && run.createdAt < this.now() - this.ttlMs) {
      this.runs.delete(runId);
      return undefined;
    }
    return run;
  }

  /** Drop runs until there is room: oldest finished or idle run first, else the oldest run. */
  _makeRoom() {
    while (this.runs.size >= this.maxRuns) {
      let victim;
      for (const [id, run] of this.runs) {
        if (!run.running) {
          victim = id;
          break;
        }
      }
      this.runs.delete(victim ?? this.runs.keys().next().value);
    }
  }

  /** Create a run. Returns { runId, traceKey }. The key is needed to read the trace. */
  create(flow) {
    this.sweep();
    this._makeRoom();
    let runId = newRunId();
    while (this.runs.has(runId)) runId = newRunId();
    const traceKey = crypto.randomBytes(32).toString('base64url');
    this.runs.set(runId, {
      events: [], bytes: 0, done: false, error: null, createdAt: this.now(), flow: flow ?? null, running: false, keyHash: keyDigest(traceKey),
    });
    return { runId, traceKey };
  }

  /**
   * (Re)open an existing run: done=false, error=null. Events are kept (append-only).
   * Returns null for an unknown or expired run, or a run created for another flow.
   */
  start(runId, flow) {
    if (!isValidRunId(runId)) return null;
    const run = this._getLive(runId);
    if (!run || (flow && run.flow && run.flow !== flow)) return null;
    run.done = false;
    run.error = null;
    return run;
  }

  has(runId) {
    return !!this._getLive(runId);
  }

  /** Flow name the run was created for, or null for an unknown run. */
  flowOf(runId) {
    return this._getLive(runId)?.flow ?? null;
  }

  isRunning(runId) {
    return !!this._getLive(runId)?.running;
  }

  runningCount() {
    this.sweep();
    let n = 0;
    for (const run of this.runs.values()) if (run.running) n += 1;
    return n;
  }

  /** Append an event. Returns the stored event, or null (unknown/invalid run or cap reached). */
  add(runId, event) {
    const status = STATUS.has(event?.status) ? event.status : 'ok';
    const stepId = String(event?.stepId ?? 'unknown');
    const run = isValidRunId(runId) ? this._getLive(runId) : undefined;
    const flow = run?.flow ?? stepId.split('-')[0];
    this.log(`flow ${flow} step ${stepId} ${status}`);
    if (!run) return null;
    if (run.events.length >= this.maxEvents) {
      run.truncated = true;
      return null;
    }
    const stored = {
      seq: run.events.length,
      stepId,
      ts: new Date(this.now()).toISOString(),
      status,
      from: ACTORS.has(event.from) ? event.from : String(event.from ?? 'unknown'),
      to: ACTORS.has(event.to) ? event.to : String(event.to ?? 'unknown'),
      label: String(event.label ?? stepId),
    };
    if (DETERMINISM.has(event.determinism)) stored.determinism = event.determinism;
    for (const k of OPTIONAL_FIELDS) {
      const v = event[k];
      if (v === undefined || v === null) continue;
      if (Array.isArray(v) && v.length === 0) continue;
      stored[k] = v;
    }
    const safe = scrubDeep(stored, this.secrets);
    const size = JSON.stringify(safe).length;
    if (run.bytes + size > this.maxRunBytes) {
      run.truncated = true;
      return null;
    }
    run.bytes += size;
    run.events.push(safe);
    return safe;
  }

  /** Mark the run finished. error: null for success, otherwise a message. */
  finish(runId, error = null) {
    const run = isValidRunId(runId) ? this._getLive(runId) : undefined;
    if (!run) return;
    run.done = true;
    run.running = false;
    run.error = error ? scrubDeep(String(error), this.secrets) : null;
  }

  /** Server-side view of a run (no key check). Unknown run: empty result. */
  get(runId, since = 0) {
    this.sweep();
    const run = this._getLive(runId);
    if (!run) return { events: [], done: false, error: null };
    const n = Number.parseInt(String(since ?? 0), 10);
    const from = Number.isInteger(n) && n > 0 ? n : 0;
    const out = { events: run.events.slice(from), done: run.done, error: run.error };
    if (run.truncated) out.truncated = true;
    return out;
  }

  /** Client view: returns null for an unknown run or a wrong key (callers must not tell which). */
  read(runId, key, since = 0) {
    this.sweep();
    if (typeof key !== 'string' || key === '' || key.length > MAX_KEY_LENGTH) return null;
    const digest = keyDigest(key);
    const run = isValidRunId(runId) ? this._getLive(runId) : undefined;
    if (!run || !crypto.timingSafeEqual(run.keyHash, digest)) return null;
    return this.get(runId, since);
  }
}
