// Shared Basin SQL guardrails, extracted verbatim from the original
// src/index.ts console path (audit run 1 behavior, 2026-10-24) so the SQL
// console and the governed query service enforce identical lexical rules.
//
// Security posture: the Basin SQL token lives only in Worker secrets, is
// never logged, and is never browser-visible. `logpush = true` ships this
// Worker's own logs into cfwork.workers_trace_events: never log secrets,
// tokens, or raw request bodies.

export interface FetcherLike {
  fetch(input: RequestInfo, init?: RequestInit): Promise<Response>;
}

export interface SqlEnv {
  BASIN_SQL_TOKEN?: string;
  ACCOUNT_ID: string;
  BUCKET: string;
}

const SQL_WRITE_KEYWORDS =
  /\b(insert|update|delete|create|drop|alter|grant|revoke|truncate|copy|attach|pragma)\b/i;
const LIMIT_ANY_RE = /\blimit\s+(\d+)\b/i;
const OFFSET_ANY_RE = /\boffset\s+(\d+)\b/i;
const MAX_QUERY_CHARS = 10_000;
const MAX_LIMIT = 2000;
const MAX_OFFSET = 20_000;
const DEFAULT_LIMIT = 200;
export { MAX_QUERY_CHARS };

// Remove -- and /* */ comments that are OUTSIDE single-quoted strings ('' is
// the in-string escape). Comment-aware, string-aware: comment markers inside
// strings are data, not comments; -- inside a block comment is comment text.
export function stripSqlComments(q: string): string {
  let out = "";
  let i = 0;
  let inString = false;
  while (i < q.length) {
    const c = q[i];
    if (inString) {
      if (c === "'") {
        if (q[i + 1] === "'") {
          out += "''";
          i += 2;
          continue;
        }
        inString = false;
      }
      out += c;
      i++;
      continue;
    }
    if (c === "'") {
      inString = true;
      out += c;
      i++;
      continue;
    }
    if (c === "-" && q[i + 1] === "-") {
      while (i < q.length && q[i] !== "\n") i++;
      out += " ";
      continue;
    }
    if (c === "/" && q[i + 1] === "*") {
      i += 2;
      while (i < q.length && !(q[i] === "*" && q[i + 1] === "/")) i++;
      i += 2;
      out += " ";
      continue;
    }
    out += c;
    i++;
  }
  return out;
}

// Blank out single-quoted string CONTENTS for structural analysis. The
// forwarded query keeps the literals; the analysis cannot be fooled by text
// inside them.
export function neutralizeStrings(s: string): string {
  let out = "";
  let i = 0;
  let inString = false;
  while (i < s.length) {
    const c = s[i];
    if (inString) {
      if (c === "'") {
        if (s[i + 1] === "'") {
          i += 2;
          continue;
        }
        inString = false;
        out += "'";
      }
      i++;
      continue;
    }
    if (c === "'") {
      inString = true;
      out += "'";
      i++;
      continue;
    }
    out += c;
    i++;
  }
  return out;
}

export type SqlCheck =
  | { ok: true; query: string }
  | { ok: false; error: string };

export function sanitizeSql(raw: string): SqlCheck {
  if (raw.length > MAX_QUERY_CHARS)
    return { ok: false, error: "Query too long (10 KB cap)." };
  const bare = stripSqlComments(raw).trim().replace(/;+\s*$/, "");
  const analysis = neutralizeStrings(bare).trim();
  if (!analysis) return { ok: false, error: "Empty query." };
  if (analysis.includes(";"))
    return { ok: false, error: "Only one statement at a time (stray semicolon)." };
  const head = analysis.replace(/^\(+\s*/, "");
  if (!/^(select|show|explain|with|describe)\b/i.test(head))
    return {
      ok: false,
      error: "Only SELECT / SHOW / EXPLAIN / DESCRIBE queries are allowed.",
    };
  if (SQL_WRITE_KEYWORDS.test(analysis))
    return { ok: false, error: "Write keywords are not allowed in the console." };
  // Forward the comment-stripped text: the checker and the backend see the
  // same string, so no comment or literal can hide live SQL from the checks.
  let q = bare;
  if (/^(select|with)\b/i.test(head)) {
    // Strict LIMIT validation: the engine's grammar accepts forms the old
    // regex did not model - the MySQL comma form "LIMIT offset, count"
    // (the guard validated the first number while the engine used the
    // second as the count), scientific notation, and LIMIT ALL. Any LIMIT
    // expression that is not plain integers in an accepted shape is
    // rejected outright (run-2 audit finding, re-applied 2026-10-24).
    const LIMIT_CLAUSE_RE = /\blimit\b([^()]*)/gi;
    let lm: RegExpExecArray | null;
    while ((lm = LIMIT_CLAUSE_RE.exec(analysis)) !== null) {
      const cm = lm[1]
        .trim()
        .match(/^(\d+)(?:\s*,\s*(\d+))?(?:\s+offset\s+(\d+))?\s*$/i);
      if (!cm)
        return { ok: false, error: "Unsupported LIMIT syntax in the console." };
      // Single number = the row count; comma form = offset, count (engine
      // semantics, live-verified). The effective count must respect the cap.
      const count = cm[2] ? parseInt(cm[2], 10) : parseInt(cm[1], 10);
      if (count > MAX_LIMIT)
        return { ok: false, error: `LIMIT is capped at ${MAX_LIMIT}.` };
      // In the comma form the first number is an offset.
      if (cm[2] && parseInt(cm[1], 10) > MAX_OFFSET)
        return { ok: false, error: `OFFSET is capped at ${MAX_OFFSET}.` };
      if (cm[3] && parseInt(cm[3], 10) > MAX_OFFSET)
        return { ok: false, error: `OFFSET is capped at ${MAX_OFFSET}.` };
    }
    const off = analysis.match(OFFSET_ANY_RE);
    if (off && parseInt(off[1], 10) > MAX_OFFSET)
      return { ok: false, error: `OFFSET is capped at ${MAX_OFFSET}.` };
    // No LIMIT anywhere in the analyzed text: append one to the stripped
    // query (trailing comments are already gone, so it always applies).
    if (!LIMIT_ANY_RE.test(analysis)) q = `${bare} LIMIT ${DEFAULT_LIMIT}`;
    // If a LIMIT exists only inside a subquery/CTE, the outer query stays
    // unbounded here; Basin SQL's server default caps returned rows.
  }
  return { ok: true, query: q };
}

// Escape a string literal for embedding into generated SQL: '' doubling only,
// no injection surface (values also pass through sanitizeSql on the result).
export function sqlLit(v: string): string {
  return `'${v.replace(/'/g, "''")}'`;
}

// Run a (pre-guarded) query against Basin SQL REST. 30 s abort: note this
// stops us waiting; it does not cancel server-side execution, and no query
// kill API is documented, so an abandoned query may still bill a scan.
export async function runSql(
  env: SqlEnv,
  query: string,
  timeoutMs = 30000,
): Promise<Response> {
  const url = `https://api.sql.cloudflarestorage.com/api/v1/accounts/${env.ACCOUNT_ID}/basin-sql/query/${env.BUCKET}`;
  const resp = await fetch(url, {
    method: "POST",
    headers: {
      Authorization: `Bearer ${env.BASIN_SQL_TOKEN}`,
      "Content-Type": "application/json",
    },
    body: JSON.stringify({ query }),
    signal: AbortSignal.timeout(timeoutMs),
  });
  return resp;
}

// Basin SQL response parsing: { success, result: { request_id, schema, rows,
// metrics }, errors: [{code, message}] }.
export interface BasinSchemaCol {
  name: string;
  descriptor?: { type?: { name?: string; nullable?: boolean } };
  type?: string;
}
export interface BasinQueryResponse {
  success?: boolean;
  result?: {
    request_id?: string;
    schema?: BasinSchemaCol[];
    rows?: Record<string, unknown>[];
    metrics?: {
      bytes_scanned?: number;
      files_scanned?: number;
      cache_hits?: number;
      r2_requests_count?: number;
    };
  };
  errors?: { code?: number; message?: string }[];
}

export async function runSqlJson(
  env: SqlEnv,
  query: string,
  timeoutMs = 30000,
): Promise<BasinQueryResponse> {
  const resp = await runSql(env, query, timeoutMs);
  const d = (await resp.json().catch(() => ({}))) as BasinQueryResponse;
  return d;
}
