const JSON_HEADERS = {
  "content-type": "application/json; charset=utf-8",
  "access-control-allow-origin": "*",
  "access-control-allow-methods": "GET, POST, OPTIONS",
  "access-control-allow-headers": "content-type, x-webhook-secret"
};

function json(data, status = 200) {
  return new Response(JSON.stringify(data, null, 2), {
    status,
    headers: JSON_HEADERS
  });
}

function normalizePath(url) {
  return new URL(url).pathname.replace(/\/+$/, "") || "/";
}

function isWebhookPath(pathname) {
  return [
    "/api/webhook",
    "/api/webhook/lionchat",
    "/api/lionchat/webhook",
    "/api/crm/orcamento",
    "/api/crm/contrato"
  ].includes(pathname);
}

function assertSecret(request, env) {
  if (!env.WEBHOOK_SECRET) return { ok: true, warning: "WEBHOOK_SECRET nao configurado" };

  const received = request.headers.get("x-webhook-secret") || "";
  if (received !== env.WEBHOOK_SECRET) {
    return { ok: false, response: json({ ok: false, error: "Webhook secret invalido" }, 401) };
  }

  return { ok: true };
}

async function readPayload(request) {
  const contentType = request.headers.get("content-type") || "";

  if (contentType.includes("application/json")) {
    return await request.json();
  }

  if (contentType.includes("application/x-www-form-urlencoded")) {
    const form = await request.formData();
    return Object.fromEntries(form.entries());
  }

  const text = await request.text();
  try {
    return JSON.parse(text);
  } catch {
    return { raw: text };
  }
}

async function forwardPayload(env, payload) {
  const targetUrl = env.FORWARD_WEBHOOK_URL || env.CRM_WEBHOOK_URL;
  if (!targetUrl) return null;

  const response = await fetch(targetUrl, {
    method: "POST",
    headers: {
      "content-type": "application/json",
      ...(env.FORWARD_WEBHOOK_SECRET ? { "x-webhook-secret": env.FORWARD_WEBHOOK_SECRET } : {})
    },
    body: JSON.stringify(payload)
  });

  return {
    status: response.status,
    ok: response.ok,
    body: await response.text()
  };
}

async function handleWebhook(request, env, ctx) {
  const secret = assertSecret(request, env);
  if (!secret.ok) return secret.response;

  let payload;
  try {
    payload = await readPayload(request);
  } catch (error) {
    return json({ ok: false, error: "Payload invalido", detail: error.message }, 400);
  }

  const event = {
    ok: true,
    receivedAt: new Date().toISOString(),
    path: normalizePath(request.url),
    source: payload.source || "aladecor",
    payload
  };

  console.log("Webhook recebido", JSON.stringify(event));

  let forwarded = null;
  try {
    forwarded = await forwardPayload(env, event);
  } catch (error) {
    forwarded = { ok: false, error: error.message };
  }

  return json({
    ok: true,
    receivedAt: event.receivedAt,
    forwarded,
    warning: secret.warning
  });
}

function handleStatus(env) {
  return json({
    ok: true,
    name: "A.L.A Decor Webhook",
    endpoints: [
      "POST /api/webhook",
      "POST /api/webhook/lionchat",
      "POST /api/lionchat/webhook",
      "POST /api/crm/orcamento",
      "POST /api/crm/contrato"
    ],
    security: env.WEBHOOK_SECRET ? "x-webhook-secret ativo" : "WEBHOOK_SECRET ainda nao configurado",
    forwarding: env.FORWARD_WEBHOOK_URL || env.CRM_WEBHOOK_URL ? "ativo" : "nao configurado"
  });
}

export default {
  async fetch(request, env, ctx) {
    if (request.method === "OPTIONS") return new Response(null, { headers: JSON_HEADERS });

    const pathname = normalizePath(request.url);

    if (pathname === "/api/webhook" && request.method === "GET") {
      return handleStatus(env);
    }

    if (isWebhookPath(pathname) && request.method === "POST") {
      return handleWebhook(request, env, ctx);
    }

    return env.ASSETS.fetch(request);
  }
};
