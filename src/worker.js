const JSON_HEADERS = {
  "content-type": "application/json; charset=utf-8",
  "access-control-allow-origin": "*",
  "access-control-allow-methods": "GET, POST, OPTIONS",
  "access-control-allow-headers": "authorization, content-type, x-chatwoot-signature, x-hub-signature-256, x-lionchat-signature, x-signature, x-webhook-secret, x-webhook-signature"
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

function timingSafeEqual(a, b) {
  if (a.length !== b.length) return false;

  let result = 0;
  for (let i = 0; i < a.length; i += 1) {
    result |= a.charCodeAt(i) ^ b.charCodeAt(i);
  }

  return result === 0;
}

async function hmacSha256Hex(secret, body) {
  const encoder = new TextEncoder();
  const key = await crypto.subtle.importKey(
    "raw",
    encoder.encode(secret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"]
  );
  const signature = await crypto.subtle.sign("HMAC", key, encoder.encode(body));
  return [...new Uint8Array(signature)].map(byte => byte.toString(16).padStart(2, "0")).join("");
}

async function assertSecret(request, env, rawBody) {
  if (!env.WEBHOOK_SECRET) return { ok: true, warning: "WEBHOOK_SECRET nao configurado" };

  const directSecret =
    request.headers.get("x-webhook-secret") ||
    request.headers.get("x-lionchat-secret") ||
    request.headers.get("x-webhook-token") ||
    (request.headers.get("authorization") || "").replace(/^Bearer\s+/i, "");

  if (directSecret && timingSafeEqual(directSecret, env.WEBHOOK_SECRET)) {
    return { ok: true, securityMode: "secret-header" };
  }

  const signature =
    request.headers.get("x-chatwoot-signature") ||
    request.headers.get("x-lionchat-signature") ||
    request.headers.get("x-webhook-signature") ||
    request.headers.get("x-hub-signature-256") ||
    request.headers.get("x-signature");

  if (signature) {
    const normalized = signature.replace(/^sha256=/i, "");
    const timestamp = request.headers.get("x-chatwoot-timestamp") || "";
    const candidates = [
      { mode: "hmac-sha256-body", body: rawBody },
      timestamp ? { mode: "hmac-sha256-timestamp-dot-body", body: `${timestamp}.${rawBody}` } : null,
      timestamp ? { mode: "hmac-sha256-timestamp-body", body: `${timestamp}${rawBody}` } : null
    ].filter(Boolean);

    for (const candidate of candidates) {
      const expected = await hmacSha256Hex(env.WEBHOOK_SECRET, candidate.body);
      if (timingSafeEqual(normalized, expected)) {
        return { ok: true, securityMode: candidate.mode };
      }
    }
  }

  return { ok: false, response: json({ ok: false, error: "Webhook secret invalido" }, 401) };
}

function parsePayload(rawBody, contentType) {
  if (contentType.includes("application/x-www-form-urlencoded")) {
    return Object.fromEntries(new URLSearchParams(rawBody).entries());
  }

  if (!rawBody) return {};

  try {
    return JSON.parse(rawBody);
  } catch {
    return { raw: rawBody };
  }
}

async function readPayload(request) {
  const contentType = request.headers.get("content-type") || "";
  const rawBody = await request.text();

  return {
    rawBody,
    payload: parsePayload(rawBody, contentType)
  };
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
  let payload;
  let rawBody;
  try {
    const body = await readPayload(request);
    payload = body.payload;
    rawBody = body.rawBody;
  } catch (error) {
    return json({ ok: false, error: "Payload invalido", detail: error.message }, 400);
  }

  const secret = await assertSecret(request, env, rawBody);
  if (!secret.ok) return secret.response;

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
    securityMode: secret.securityMode || "none",
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
    securityMode: event.securityMode,
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
    security: env.WEBHOOK_SECRET ? "secret/header ou assinatura HMAC ativa" : "WEBHOOK_SECRET ainda nao configurado",
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
