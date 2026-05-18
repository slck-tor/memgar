import assert from "node:assert/strict";
import test from "node:test";

import {
  MemgarCliClient,
  MemgarError,
  MemgarGatewayClient,
  parseMemgarCliJson,
} from "../src/index.js";

test("gateway client sends health request with auth header", async () => {
  const calls = [];
  const fakeFetch = async (url, init) => {
    calls.push({ url, init });
    return new Response(JSON.stringify({ status: "ok" }), {
      status: 200,
      headers: { "content-type": "application/json" },
    });
  };

  const client = new MemgarGatewayClient({
    baseUrl: "http://localhost:8080/",
    apiKey: "test-key",
    fetch: fakeFetch,
  });

  const result = await client.health();

  assert.equal(result.status, "ok");
  assert.equal(calls[0].url, "http://localhost:8080/__memgar/health");
  assert.equal(calls[0].init.headers.authorization, "Bearer test-key");
});

test("gateway client throws MemgarError for blocked responses", async () => {
  const fakeFetch = async () => new Response(
    JSON.stringify({ error: { type: "memgar_gateway_blocked", message: "blocked" } }),
    { status: 403, headers: { "content-type": "application/json" } },
  );

  const client = new MemgarGatewayClient({ fetch: fakeFetch });

  await assert.rejects(
    () => client.chatCompletions({ model: "test", messages: [] }),
    (error) => {
      assert.ok(error instanceof MemgarError);
      assert.equal(error.status, 403);
      assert.equal(error.code, "memgar_gateway_blocked");
      return true;
    },
  );
});

test("CLI client parses JSON returned by memgar analyze", async () => {
  const runner = async (command, args) => {
    assert.equal(command, "memgar");
    assert.deepEqual(args, ["analyze", "User likes concise answers", "--json", "--strict"]);
    return {
      code: 0,
      stdout: JSON.stringify({ decision: "allow", risk_score: 2 }),
      stderr: "",
    };
  };

  const client = new MemgarCliClient({ strict: true, runner });
  const result = await client.analyze("User likes concise answers");

  assert.equal(result.decision, "allow");
  assert.equal(result.risk_score, 2);
});

test("parseMemgarCliJson strips ANSI and surrounding text", () => {
  const output = "\u001b[32mresult\u001b[0m\n{\"decision\":\"block\",\"risk_score\":91}\n";
  const parsed = parseMemgarCliJson(output);

  assert.equal(parsed.decision, "block");
  assert.equal(parsed.risk_score, 91);
});
