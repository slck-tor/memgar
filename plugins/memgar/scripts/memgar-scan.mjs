import { spawn } from "node:child_process";

function stripAnsi(value) {
  return String(value || "").replace(/\x1B(?:[@-Z\-_]|\[[0-?]*[ -/]*[@-~])/g, "");
}

function parseJson(output) {
  const clean = stripAnsi(output).trim();
  try {
    return JSON.parse(clean);
  } catch {
    const start = clean.indexOf("{");
    const end = clean.lastIndexOf("}");
    if (start >= 0 && end > start) {
      return JSON.parse(clean.slice(start, end + 1));
    }
    throw new Error("Unable to parse memgar analyze JSON output");
  }
}

const content = process.argv.slice(2).join(" ").trim();
if (!content) {
  console.error("Usage: memgar-scan <memory text>");
  process.exit(64);
}

const command = process.env.MEMGAR_CLI || "memgar";
const args = ["analyze", content, "--json"];
if (process.env.MEMGAR_STRICT === "1" || process.env.MEMGAR_STRICT === "true") {
  args.push("--strict");
}

const child = spawn(command, args, {
  env: process.env,
  shell: false,
  windowsHide: true,
});

let stdout = "";
let stderr = "";
child.stdout.on("data", (chunk) => {
  stdout += chunk;
});
child.stderr.on("data", (chunk) => {
  stderr += chunk;
});
child.on("error", (error) => {
  console.error(JSON.stringify({ error: "failed_to_start_memgar_cli", message: error.message }, null, 2));
  process.exit(1);
});
child.on("close", (code) => {
  try {
    const result = parseJson(stdout);
    console.log(JSON.stringify(result, null, 2));
    if (process.env.MEMGAR_FAIL_ON_BLOCK === "1" && result.decision === "block") {
      process.exit(2);
    }
    process.exit(code && !stdout ? code : 0);
  } catch (error) {
    console.error(JSON.stringify({
      error: "memgar_scan_failed",
      message: error.message,
      exit_code: code,
      stderr: stripAnsi(stderr),
    }, null, 2));
    process.exit(code || 1);
  }
});
