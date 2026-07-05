const JSON_HEADERS = {
  "content-type": "application/json; charset=utf-8",
  "access-control-allow-origin": "*",
  "access-control-allow-methods": "GET, POST, OPTIONS",
  "access-control-allow-headers": "content-type, x-webhook-secret"
};

const DEFAULT_ALLOWED_INBOX_IDS = ["230"];
const DEFAULT_ALLOWED_PHONE_NUMBERS = ["5511977803209"];

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

function isLionChatPath(pathname) {
  return pathname === "/api/webhook/lionchat" || pathname === "/api/lionchat/webhook";
}

function normalizeList(value, fallback) {
  if (!value) return fallback;
  return String(value)
    .split(",")
    .map(item => item.trim())
    .filter(Boolean);
}

function collectValuesByKey(input, wantedKeys, found = new Set()) {
  if (!input || typeof input !== "object") return found;

  if (Array.isArray(input)) {
    input.forEach(item => collectValuesByKey(item, wantedKeys, found));
    return found;
  }

  for (const [key, value] of Object.entries(input)) {
    if (wantedKeys.includes(key) && value !== null && value !== undefined) {
      found.add(String(value));
    }

    if (value && typeof value === "object") {
      collectValuesByKey(value, wantedKeys, found);
    }
  }

  return found;
}

function collectInboxIds(input, found = new Set()) {
  if (!input || typeof input !== "object") return found;

  if (Array.isArray(input)) {
    input.forEach(item => collectInboxIds(item, found));
    return found;
  }

  for (const [key, value] of Object.entries(input)) {
    if ((key === "inbox_id" || key === "inboxId") && value !== null && value !== undefined) {
      found.add(String(value));
    }

    if (key === "inbox" && value && typeof value === "object" && value.id !== null && value.id !== undefined) {
      found.add(String(value.id));
    }

    if (value && typeof value === "object") {
      collectInboxIds(value, found);
    }
  }

  return found;
}

function onlyDigits(value) {
  return String(value || "").replace(/\D/g, "");
}

function validateLionChatInbox(payload, env) {
  const allowedInboxIds = normalizeList(env.ALLOWED_LIONCHAT_INBOX_IDS, DEFAULT_ALLOWED_INBOX_IDS);
  const allowedPhones = normalizeList(env.ALLOWED_LIONCHAT_PHONE_NUMBERS, DEFAULT_ALLOWED_PHONE_NUMBERS).map(onlyDigits);
  const inboxCandidates = collectInboxIds(payload);
  const phoneCandidates = collectValuesByKey(payload, ["phone_number", "phoneNumber", "phone", "identifier", "source_id"]);

  const inboxMatch = [...inboxCandidates].some(value => allowedInboxIds.includes(String(value)));
  const phoneMatch = [...phoneCandidates].some(value => allowedPhones.includes(onlyDigits(value)));

  if (inboxMatch || phoneMatch) {
    return { ok: true, inboxCandidates: [...inboxCandidates], phoneCandidates: [...phoneCandidates] };
  }

  return {
    ok: false,
    allowedInboxIds,
    allowedPhones,
    inboxCandidates: [...inboxCandidates],
    phoneCandidates: [...phoneCandidates]
  };
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

  const pathname = normalizePath(request.url);
  let inboxValidation = null;

  if (isLionChatPath(pathname)) {
    inboxValidation = validateLionChatInbox(payload, env);
    if (!inboxValidation.ok) {
      console.log("Evento LionChat ignorado por inbox diferente", JSON.stringify(inboxValidation));
      return json({
        ok: true,
        ignored: true,
        reason: "Evento de outra inbox/numero do LionChat",
        allowedInboxIds: inboxValidation.allowedInboxIds,
        allowedPhones: inboxValidation.allowedPhones,
        receivedInboxCandidates: inboxValidation.inboxCandidates,
        receivedPhoneCandidates: inboxValidation.phoneCandidates
      }, 202);
    }
  }

  const event = {
    ok: true,
    receivedAt: new Date().toISOString(),
    path: pathname,
    source: payload.source || "aladecor",
    inboxValidation,
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
    lionchat_filter: {
      allowed_inbox_ids: normalizeList(env.ALLOWED_LIONCHAT_INBOX_IDS, DEFAULT_ALLOWED_INBOX_IDS),
      allowed_phone_numbers: normalizeList(env.ALLOWED_LIONCHAT_PHONE_NUMBERS, DEFAULT_ALLOWED_PHONE_NUMBERS)
    },
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
