const baseUrl = (process.env.MEMGAR_GATEWAY_URL || "http://127.0.0.1:8080").replace(/\/+$/, "");

async function getJson(path) {
  const response = await fetch(baseUrl + path, {
    headers: { accept: "application/json" },
  });
  const text = await response.text();
  let body;
  try {
    body = text ? JSON.parse(text) : null;
  } catch {
    body = text;
  }
  if (!response.ok) {
    const message = body?.error?.message || body?.message || "HTTP " + response.status;
    throw new Error(message);
  }
  return body;
}

try {
  const health = await getJson("/__memgar/health");
  let policy = null;
  try {
    policy = await getJson("/__memgar/policy");
  } catch (error) {
    policy = { error: error.message };
  }

  const result = {
    gateway_url: baseUrl,
    health,
    policy,
  };
  console.log(JSON.stringify(result, null, 2));

  if (health?.status && health.status !== "ok") {
    process.exitCode = 1;
  }
} catch (error) {
  console.error(JSON.stringify({ gateway_url: baseUrl, error: error.message }, null, 2));
  process.exitCode = 1;
}
