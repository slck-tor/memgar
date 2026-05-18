import { spawn } from "node:child_process";

const DEFAULT_BASE_URL = "http://127.0.0.1:8080";
const ENV = globalThis.process && globalThis.process.env ? globalThis.process.env : {};

export class MemgarError extends Error {
  constructor(message, options = {}) {
    super(message, { cause: options.cause });
    this.name = "MemgarError";
    this.status = options.status;
    this.code = options.code;
    this.response = options.response;
  }
}

function normalizeBaseUrl(baseUrl = DEFAULT_BASE_URL) {
  if (typeof baseUrl !== "string" || baseUrl.trim() === "") {
    throw new TypeError("baseUrl must be a non-empty string");
  }
  return baseUrl.replace(/\/+$/, "");
}

function buildUrl(baseUrl, path) {
  const safePath = String(path || "").replace(/^\/+/, "");
  return new URL(safePath, baseUrl + "/").toString();
}

function parseJsonResponse(text) {
  if (!text) {
    return null;
  }
  try {
    return JSON.parse(text);
  } catch {
    return text;
  }
}

function timeoutSignal(timeoutMs, externalSignal) {
  if (!timeoutMs && !externalSignal) {
    return { signal: undefined, cleanup: () => {} };
  }
  const controller = new AbortController();
  let timer;
  let onAbort;

  if (externalSignal) {
    if (externalSignal.aborted) {
      controller.abort(externalSignal.reason);
    } else {
      onAbort = () => controller.abort(externalSignal.reason);
      externalSignal.addEventListener("abort", onAbort, { once: true });
    }
  }

  if (timeoutMs && timeoutMs > 0) {
    timer = setTimeout(
      () => controller.abort(new Error("Memgar request timed out after " + timeoutMs + "ms")),
      timeoutMs,
    );
  }

  return {
    signal: controller.signal,
    cleanup: () => {
      if (timer) clearTimeout(timer);
      if (externalSignal && onAbort) externalSignal.removeEventListener("abort", onAbort);
    },
  };
}

export class MemgarGatewayClient {
  constructor(options = {}) {
    this.baseUrl = normalizeBaseUrl(
      options.baseUrl || ENV.MEMGAR_GATEWAY_URL || DEFAULT_BASE_URL,
    );
    this.apiKey = options.apiKey || ENV.MEMGAR_API_KEY || "";
    this.timeoutMs = options.timeoutMs ?? 30000;
    this.fetch = options.fetch || globalThis.fetch;
    this.headers = { ...(options.headers || {}) };

    if (typeof this.fetch !== "function") {
      throw new TypeError(
        "MemgarGatewayClient requires fetch; use Node.js 18+ or pass options.fetch",
      );
    }
  }

  async request(method, path, options = {}) {
    const body = options.body;
    const headers = {
      accept: "application/json",
      ...this.headers,
      ...(options.headers || {}),
    };

    const init = {
      method,
      headers,
    };

    if (this.apiKey) {
      headers.authorization = "Bearer " + this.apiKey;
    }

    if (body !== undefined) {
      headers["content-type"] = headers["content-type"] || "application/json";
      init.body = typeof body === "string" ? body : JSON.stringify(body);
    }

    const timeout = timeoutSignal(options.timeoutMs ?? this.timeoutMs, options.signal);
    init.signal = timeout.signal;

    try {
      const response = await this.fetch(buildUrl(this.baseUrl, path), init);
      const text = await response.text();
      const parsed = parseJsonResponse(text);

      if (!response.ok) {
        const message =
          parsed?.error?.message ||
          parsed?.message ||
          "Memgar request failed with status " + response.status;
        throw new MemgarError(message, {
          status: response.status,
          code: parsed?.error?.type || parsed?.code,
          response: parsed,
        });
      }

      return parsed;
    } catch (error) {
      if (error instanceof MemgarError) {
        throw error;
      }
      throw new MemgarError(error.message || "Memgar request failed", { cause: error });
    } finally {
      timeout.cleanup();
    }
  }

  health(options = {}) {
    return this.request("GET", "/__memgar/health", options);
  }

  policy(options = {}) {
    return this.request("GET", "/__memgar/policy", options);
  }

  chatCompletions(payload, options = {}) {
    return this.request("POST", "/v1/chat/completions", { ...options, body: payload });
  }

  responses(payload, options = {}) {
    return this.request("POST", "/v1/responses", { ...options, body: payload });
  }

  openAICompatible() {
    return {
      chat: {
        completions: {
          create: (payload, options = {}) => this.chatCompletions(payload, options),
        },
      },
      responses: {
        create: (payload, options = {}) => this.responses(payload, options),
      },
    };
  }
}

export function stripAnsi(value) {
  return String(value || "").replace(/\x1B(?:[@-Z\-_]|\[[0-?]*[ -/]*[@-~])/g, "");
}

export function parseMemgarCliJson(output) {
  const clean = stripAnsi(output).trim();
  if (!clean) {
    throw new MemgarError("Memgar CLI returned no JSON output");
  }
  try {
    return JSON.parse(clean);
  } catch {
    const start = clean.indexOf("{");
    const end = clean.lastIndexOf("}");
    if (start >= 0 && end > start) {
      return JSON.parse(clean.slice(start, end + 1));
    }
    throw new MemgarError("Unable to parse Memgar CLI JSON output", { response: clean });
  }
}

function runCommand(command, args, options = {}) {
  return new Promise((resolve, reject) => {
    const child = spawn(command, args, {
      cwd: options.cwd,
      env: { ...ENV, ...(options.env || {}) },
      shell: false,
      windowsHide: true,
    });

    let stdout = "";
    let stderr = "";
    let settled = false;
    let timer;

    if (options.timeoutMs && options.timeoutMs > 0) {
      timer = setTimeout(() => {
        if (!settled) {
          child.kill("SIGTERM");
          settled = true;
          reject(new MemgarError("Memgar CLI timed out after " + options.timeoutMs + "ms"));
        }
      }, options.timeoutMs);
    }

    child.stdout.on("data", (chunk) => {
      stdout += chunk;
    });
    child.stderr.on("data", (chunk) => {
      stderr += chunk;
    });
    child.on("error", (error) => {
      if (timer) clearTimeout(timer);
      if (!settled) {
        settled = true;
        reject(new MemgarError("Failed to start Memgar CLI: " + error.message, { cause: error }));
      }
    });
    child.on("close", (code) => {
      if (timer) clearTimeout(timer);
      if (!settled) {
        settled = true;
        resolve({ code, stdout, stderr });
      }
    });
  });
}

export class MemgarCliClient {
  constructor(options = {}) {
    this.command = options.command || ENV.MEMGAR_CLI || "memgar";
    this.timeoutMs = options.timeoutMs ?? 30000;
    this.strict = Boolean(options.strict);
    this.runner = options.runner || runCommand;
  }

  async analyze(content, options = {}) {
    if (typeof content !== "string" || content.trim() === "") {
      throw new TypeError("content must be a non-empty string");
    }
    const args = ["analyze", content, "--json"];
    if (options.strict ?? this.strict) {
      args.push("--strict");
    }

    const result = await this.runner(this.command, args, {
      cwd: options.cwd,
      env: options.env,
      timeoutMs: options.timeoutMs ?? this.timeoutMs,
    });

    if (result.code !== 0 && !result.stdout) {
      throw new MemgarError("Memgar CLI failed with exit code " + result.code, {
        status: result.code,
        response: stripAnsi(result.stderr || ""),
      });
    }
    return parseMemgarCliJson(result.stdout);
  }
}

export class MemgarClient extends MemgarGatewayClient {}

export default MemgarClient;
