// In-memory run event store: the contract with the frontend.
import { scrubDeep } from './mask.js';

export const RUN_ID_RE = /^[A-Za-z0-9_-]{8,64}$/;
export const ACTORS = new Set([
  'user', 'browser', 'api', 'daemon', 'device', 'entra', 'graph', 'agent', 'mcpclient', 'mcpserver', 'llm', 'webapp',
]);
const DETERMINISM = new Set(['protocol', 'ai', 'human', 'policy']);
const STATUS = new Set(['ok', 'error', 'pending']);
const OPTIONAL_FIELDS = ['request', 'response', 'tokens', 'checks', 'note', 'data'];

export function isValidRunId(runId) {
  return typeof runId === 'string' && RUN_ID_RE.test(runId);
}

function defaultLog(line) {
  console.log(line);
}

export class TraceStore {
  constructor({
    ttlMs = 30 * 60 * 1000,
    maxEvents = 500,
    maxRuns = 1000,
    now = () => Date.now(),
    secrets = [],
    log = defaultLog,
  } = {}) {
    this.ttlMs = ttlMs;
    this.maxEvents = maxEvents;
    this.maxRuns = maxRuns;
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
    const run = this.runs.get(runId);
    if (run && run.createdAt < this.now() - this.ttlMs) {
      this.runs.delete(runId);
      return undefined;
    }
    return run;
  }

  /** Create the run if needed and (re)open it: done=false, error=null. Events are kept (append-only). */
  start(runId, flow) {
    if (!isValidRunId(runId)) return null;
    this.sweep();
    let run = this._getLive(runId);
    if (!run) {
      while (this.runs.size >= this.maxRuns) this.runs.delete(this.runs.keys().next().value);
      run = { events: [], done: false, error: null, createdAt: this.now(), flow, running: false };
      this.runs.set(runId, run);
    }
    run.done = false;
    run.error = null;
    if (flow) run.flow = flow;
    return run;
  }

  isRunning(runId) {
    return !!this._getLive(runId)?.running;
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

  get(runId, since = 0) {
    this.sweep();
    const run = this._getLive(runId);
    if (!run) return { events: [], done: false, error: null };
    const n = Number.parseInt(String(since ?? 0), 10);
    const from = Number.isInteger(n) && n > 0 ? n : 0;
    return { events: run.events.slice(from), done: run.done, error: run.error };
  }
}
