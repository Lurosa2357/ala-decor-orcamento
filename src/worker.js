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
    "/api/crm/orcamento-imagem",
    "/api/crm/orcamento",
    "/api/crm/contrato"
  ].includes(pathname);
}

function isLionChatPath(pathname) {
  return pathname === "/api/webhook/lionchat" || pathname === "/api/lionchat/webhook";
}

function isCrmPath(pathname) {
  return pathname === "/api/crm/orcamento" || pathname === "/api/crm/orcamento-imagem" || pathname === "/api/crm/contrato";
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

function parseSearchParams(url) {
  return Object.fromEntries(new URL(url).searchParams.entries());
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

function toNumber(value) {
  if (typeof value === "number") return value;
  const normalized = String(value || "").replace(",", ".").replace(/[^\d.]/g, "");
  return parseFloat(normalized) || 0;
}

function formatMoney(value) {
  return "R$ " + value.toLocaleString("pt-BR", { minimumFractionDigits: 2, maximumFractionDigits: 2 });
}

function escapeXml(value) {
  return String(value ?? "")
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}

function buildBudgetImageUrl(requestUrl, payload) {
  const url = new URL(requestUrl);
  url.pathname = "/api/crm/orcamento-imagem";
  url.search = "";

  for (const [key, value] of Object.entries(payload)) {
    if (value !== null && value !== undefined && String(value).trim()) {
      url.searchParams.set(key, String(value));
    }
  }

  return url.toString();
}

function buildBudget(payload) {
  const tipoRaw = String(payload.tipo_piso || payload.tipo || "").toLowerCase();
  const tipo = tipoRaw.includes("vin") ? "vinilico" : "laminado";
  const area = toNumber(payload.area_m2 || payload.area || payload.metragem || payload.medida_local);
  const portas = Math.max(0, Math.round(toNumber(payload.qtd_portas || payload.portas)));
  const nome = payload.nome_cliente || payload.cliente || payload.nome || "cliente";
  const ambiente = payload.ambiente || payload.local || "ambiente informado";

  if (!area) {
    return {
      status: "precisa_dados",
      mensagem: "Consigo montar sim. Me manda a metragem em m² ou uma foto/PDF da planta com as medidas visíveis?"
    };
  }

  const precoM2 = tipo === "vinilico" ? 145 : 125;
  const freteInstalacaoBase = 160;
  const ajustePortas = portas * 44.8;
  const total = area * precoM2 + freteInstalacaoBase + ajustePortas;

  return {
    status: "orcamento_estimado",
    tipo_piso: tipo,
    area_m2: area,
    qtd_portas: portas,
    preco_m2: precoM2,
    frete_instalacao_base: freteInstalacaoBase,
    ajuste_portas: ajustePortas,
    valor_total: total,
    mensagem: [
      `Fechado, ${nome}! Com base nas informações enviadas:`,
      `${tipo === "vinilico" ? "piso vinílico" : "piso laminado"}, ${area.toLocaleString("pt-BR")} m², ${portas} porta${portas === 1 ? "" : "s"} no ${ambiente}.`,
      `Orçamento estimado: ${formatMoney(total)}.`,
      "Esse valor é uma estimativa inicial. Para fechar certinho, a equipe confere a planta/medidas e confirma o modelo do piso."
    ].join("\n")
  };
}

function renderBudgetSvg(payload) {
  const result = buildBudget(payload);
  const nome = payload.nome_cliente || payload.cliente || payload.nome || "Cliente";
  const ambiente = payload.ambiente || payload.local || "Ambiente informado";
  const piso = result.tipo_piso === "vinilico" ? "Piso vinilico" : "Piso laminado";
  const area = result.area_m2 || toNumber(payload.area_m2 || payload.area || payload.metragem || payload.medida_local);
  const portas = result.qtd_portas ?? Math.max(0, Math.round(toNumber(payload.qtd_portas || payload.portas)));
  const total = result.valor_total || 0;
  const precoM2 = result.preco_m2 || (result.tipo_piso === "vinilico" ? 145 : 125);
  const ajustePortas = result.ajuste_portas || portas * 44.8;

  const svg = `<?xml version="1.0" encoding="UTF-8"?>
<svg xmlns="http://www.w3.org/2000/svg" width="1080" height="1350" viewBox="0 0 1080 1350">
  <rect width="1080" height="1350" fill="#f3f0e8"/>
  <rect x="70" y="70" width="940" height="1210" rx="34" fill="#ffffff" stroke="#1f2933" stroke-width="3"/>
  <rect x="70" y="70" width="940" height="210" rx="34" fill="#111827"/>
  <text x="120" y="155" font-family="Arial, sans-serif" font-size="54" font-weight="700" fill="#ffffff">A.L.A DECOR</text>
  <text x="120" y="220" font-family="Arial, sans-serif" font-size="28" fill="#e5e7eb">Pisos vinilicos e laminados</text>
  <text x="120" y="345" font-family="Arial, sans-serif" font-size="46" font-weight="700" fill="#111827">Orcamento inicial</text>
  <text x="120" y="400" font-family="Arial, sans-serif" font-size="25" fill="#6b7280">Estimativa para conferencia da equipe</text>

  <rect x="120" y="460" width="840" height="340" rx="22" fill="#f9fafb" stroke="#d1d5db" stroke-width="2"/>
  <text x="160" y="535" font-family="Arial, sans-serif" font-size="28" fill="#6b7280">Cliente</text>
  <text x="160" y="585" font-family="Arial, sans-serif" font-size="40" font-weight="700" fill="#111827">${escapeXml(nome)}</text>
  <text x="160" y="665" font-family="Arial, sans-serif" font-size="28" fill="#6b7280">Ambiente</text>
  <text x="160" y="715" font-family="Arial, sans-serif" font-size="36" font-weight="700" fill="#111827">${escapeXml(ambiente)}</text>

  <rect x="120" y="840" width="260" height="145" rx="20" fill="#eef2ff"/>
  <text x="150" y="895" font-family="Arial, sans-serif" font-size="24" fill="#4f46e5">Piso</text>
  <text x="150" y="945" font-family="Arial, sans-serif" font-size="31" font-weight="700" fill="#111827">${escapeXml(piso)}</text>

  <rect x="410" y="840" width="230" height="145" rx="20" fill="#ecfdf5"/>
  <text x="440" y="895" font-family="Arial, sans-serif" font-size="24" fill="#047857">Metragem</text>
  <text x="440" y="945" font-family="Arial, sans-serif" font-size="36" font-weight="700" fill="#111827">${escapeXml(area.toLocaleString("pt-BR"))} m2</text>

  <rect x="670" y="840" width="290" height="145" rx="20" fill="#fff7ed"/>
  <text x="700" y="895" font-family="Arial, sans-serif" font-size="24" fill="#c2410c">Portas</text>
  <text x="700" y="945" font-family="Arial, sans-serif" font-size="36" font-weight="700" fill="#111827">${escapeXml(portas)} porta${portas === 1 ? "" : "s"}</text>

  <line x1="120" y1="1050" x2="960" y2="1050" stroke="#d1d5db" stroke-width="2"/>
  <text x="120" y="1110" font-family="Arial, sans-serif" font-size="27" fill="#374151">Base: ${escapeXml(area.toLocaleString("pt-BR"))} m2 x ${formatMoney(precoM2)}</text>
  <text x="120" y="1160" font-family="Arial, sans-serif" font-size="27" fill="#374151">Instalacao/frete base: ${formatMoney(160)}</text>
  <text x="120" y="1210" font-family="Arial, sans-serif" font-size="27" fill="#374151">Ajuste de portas: ${formatMoney(ajustePortas)}</text>

  <rect x="120" y="1245" width="840" height="92" rx="20" fill="#111827"/>
  <text x="160" y="1305" font-family="Arial, sans-serif" font-size="32" font-weight="700" fill="#ffffff">Total estimado: ${escapeXml(formatMoney(total))}</text>
</svg>`;

  return new Response(svg, {
    headers: {
      "content-type": "image/svg+xml; charset=utf-8",
      "access-control-allow-origin": "*"
    }
  });
}

async function handleCrmApi(pathname, payload, requestUrl) {
  if (pathname === "/api/crm/orcamento-imagem") {
    return renderBudgetSvg(payload);
  }

  if (pathname === "/api/crm/orcamento") {
    const result = buildBudget(payload);
    console.log("Orcamento solicitado pelo CRM", JSON.stringify({ payload, result }));
    return json({
      ok: true,
      ...result,
      imagem_url: buildBudgetImageUrl(requestUrl, payload)
    });
  }

  if (pathname === "/api/crm/contrato") {
    return json({
      ok: true,
      status: "recebido",
      mensagem: "Dados de contrato recebidos. Vou preparar o contrato e chamar um atendente para conferir antes do envio."
    });
  }

  return null;
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

  const pathname = normalizePath(request.url);
  if (isCrmPath(pathname)) {
    const crmResponse = await handleCrmApi(pathname, payload, request.url);
    if (crmResponse) return crmResponse;
  }

  const secret = await assertSecret(request, env, rawBody);
  if (!secret.ok) return secret.response;

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
      "GET /api/crm/orcamento",
      "GET /api/crm/orcamento-imagem",
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

    if (isCrmPath(pathname) && request.method === "GET") {
      return handleCrmApi(pathname, parseSearchParams(request.url), request.url);
    }

    if (isWebhookPath(pathname) && request.method === "POST") {
      return handleWebhook(request, env, ctx);
    }

    return env.ASSETS.fetch(request);
  }
};
