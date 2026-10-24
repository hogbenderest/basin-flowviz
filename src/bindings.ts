// Minimal binding shapes so service modules do not depend on the generated
// worker-configuration.d.ts (which is gitignored and regenerated per machine).
export interface D1Statement {
  bind(...vals: unknown[]): D1Statement;
  first<T = unknown>(): Promise<T | null>;
  all<T = unknown>(): Promise<{ results: T[] } | T[]>;
  run(): Promise<unknown>;
}
export interface D1DatabaseLike {
  prepare(query: string): D1Statement;
  batch?(stmts: D1Statement[]): Promise<unknown>;
  exec?(query: string): Promise<unknown>;
}
export interface R2BucketLike {
  put(
    key: string,
    value: string | ReadableStream | ArrayBuffer,
    opts?: { httpMetadata?: Record<string, string> },
  ): Promise<unknown>;
  get(key: string): Promise<{ text: () => Promise<string>; body: ReadableStream } | null>;
}
export interface AiLike {
  run(model: string, input: unknown): Promise<unknown>;
}

export interface WorkflowLike {
  create(opts: { id?: string; params: unknown }): Promise<unknown>;
}

export interface ServiceEnv {
  BASIN_SQL_TOKEN?: string;
  ACCOUNT_ID: string;
  BUCKET: string;
  REPORTS_D1?: D1DatabaseLike;
  REPORTS_R2?: R2BucketLike;
  AI?: AiLike;
  ASK_MODEL?: string;
  SCAN_BUDGET_MB?: string;
  ASK_PER_MINUTE?: string;
}
