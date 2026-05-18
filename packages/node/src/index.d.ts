export interface MemgarRequestOptions {
  headers?: Record<string, string>;
  signal?: AbortSignal;
  timeoutMs?: number;
  body?: unknown;
}

export interface MemgarGatewayClientOptions {
  baseUrl?: string;
  apiKey?: string;
  timeoutMs?: number;
  fetch?: typeof fetch;
  headers?: Record<string, string>;
}

export interface MemgarCliClientOptions {
  command?: string;
  timeoutMs?: number;
  strict?: boolean;
  runner?: MemgarCommandRunner;
}

export interface MemgarCommandResult {
  code: number | null;
  stdout: string;
  stderr: string;
}

export type MemgarCommandRunner = (
  command: string,
  args: string[],
  options: { cwd?: string; env?: Record<string, string>; timeoutMs?: number },
) => Promise<MemgarCommandResult>;

export interface MemgarAnalyzeOptions {
  cwd?: string;
  env?: Record<string, string>;
  strict?: boolean;
  timeoutMs?: number;
}

export class MemgarError extends Error {
  status?: number | null;
  code?: string;
  response?: unknown;
  constructor(message: string, options?: { status?: number | null; code?: string; response?: unknown; cause?: unknown });
}

export class MemgarGatewayClient {
  baseUrl: string;
  apiKey: string;
  timeoutMs: number;
  headers: Record<string, string>;
  constructor(options?: MemgarGatewayClientOptions);
  request<T = unknown>(method: string, path: string, options?: MemgarRequestOptions): Promise<T>;
  health<T = unknown>(options?: MemgarRequestOptions): Promise<T>;
  policy<T = unknown>(options?: MemgarRequestOptions): Promise<T>;
  chatCompletions<T = unknown>(payload: unknown, options?: MemgarRequestOptions): Promise<T>;
  responses<T = unknown>(payload: unknown, options?: MemgarRequestOptions): Promise<T>;
  openAICompatible(): {
    chat: { completions: { create: <T = unknown>(payload: unknown, options?: MemgarRequestOptions) => Promise<T> } };
    responses: { create: <T = unknown>(payload: unknown, options?: MemgarRequestOptions) => Promise<T> };
  };
}

export class MemgarCliClient {
  command: string;
  timeoutMs: number;
  strict: boolean;
  constructor(options?: MemgarCliClientOptions);
  analyze<T = unknown>(content: string, options?: MemgarAnalyzeOptions): Promise<T>;
}

export class MemgarClient extends MemgarGatewayClient {}

export function stripAnsi(value: unknown): string;
export function parseMemgarCliJson<T = unknown>(output: string): T;

export default MemgarClient;
