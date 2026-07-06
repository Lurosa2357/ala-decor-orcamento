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
    "/api/crm/gerar-orcamento",
    "/api/crm/contrato"
  ].includes(pathname);
}

function isLionChatPath(pathname) {
  return pathname === "/api/webhook/lionchat" || pathname === "/api/lionchat/webhook";
}

function isCrmPath(pathname) {
  return pathname === "/api/crm/orcamento" ||
    pathname === "/api/crm/orcamento-imagem" ||
    pathname === "/api/crm/gerar-orcamento" ||
    pathname === "/api/crm/contrato";
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
  const valorInformado = toNumber(payload.valor_total || payload.valor || payload.total);

  if (!area) {
    return {
      status: "precisa_dados",
      mensagem: "Consigo montar sim. Me manda a metragem em m² ou uma foto/PDF da planta com as medidas visíveis?"
    };
  }

  const precoM2 = tipo === "vinilico" ? 145 : 125;
  const freteInstalacaoBase = 160;
  const ajustePortas = portas * 44.8;
  const total = valorInformado || (area * precoM2 + freteInstalacaoBase + ajustePortas);

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
  const telefone = payload.telefone || payload.phone || payload.whatsapp || "-";
  const endereco = payload.endereco || payload.address || "A confirmar";
  const numero = payload.orcamento_numero || payload.numero || payload.id || "AUTO";
  const emissao = payload.emissao || new Date().toLocaleDateString("pt-BR");
  const validade = payload.validade || "7 dias";
  const ambiente = payload.ambiente || payload.local || "ambiente informado";
  const piso = result.tipo_piso === "vinilico" ? "Piso vinilico" : "Piso laminado";
  const area = result.area_m2 || toNumber(payload.area_m2 || payload.area || payload.metragem || payload.medida_local);
  const portas = result.qtd_portas ?? Math.max(0, Math.round(toNumber(payload.qtd_portas || payload.portas)));
  const total = result.valor_total || 0;
  const precoM2 = area ? total / area : result.preco_m2 || (result.tipo_piso === "vinilico" ? 145 : 125);
  const entrada = total * 0.6;
  const servico = [
    `Fornecimento e instalacao de ${piso.toLowerCase()}`,
    `${ambiente} - ${area.toLocaleString("pt-BR", { maximumFractionDigits: 2 })} m2`,
    portas ? `${portas} porta${portas === 1 ? "" : "s"} / passagem${portas === 1 ? "" : "ns"} considerada${portas === 1 ? "" : "s"}` : "Portas/passagens a confirmar"
  ];

  const svg = `<?xml version="1.0" encoding="UTF-8"?>
<svg xmlns="http://www.w3.org/2000/svg" width="1080" height="1528" viewBox="0 0 1080 1528">
  <rect width="1080" height="1528" fill="#f0f0f8"/>
  <rect x="60" y="54" width="960" height="1420" rx="8" fill="#ffffff"/>
  <rect x="60" y="54" width="960" height="172" fill="#231a72"/>
  <text x="95" y="128" font-family="Georgia, serif" font-size="46" font-weight="700" fill="#f0eadf">A.L.A DECOR</text>
  <text x="95" y="175" font-family="Arial, sans-serif" font-size="22" fill="#f5a04a">Pisos Laminados e Vinilicos</text>
  <text x="610" y="100" font-family="Arial, sans-serif" font-size="21" font-weight="700" fill="#ffffff">A.L.A Decor Pisos Laminados e Vinilicos</text>
  <text x="610" y="132" font-family="Arial, sans-serif" font-size="18" fill="#ffffff">CNPJ: 41.374.458/0001-98</text>
  <text x="610" y="162" font-family="Arial, sans-serif" font-size="18" fill="#ffffff">Rua Bauru, 129 - Jardim do Carmo</text>
  <text x="610" y="192" font-family="Arial, sans-serif" font-size="18" fill="#ffffff">(11) 97780-3209 | @a.l.a_decoracoes</text>

  <rect x="95" y="266" width="890" height="104" fill="#ffffff" stroke="#dde3ec"/>
  <rect x="95" y="266" width="890" height="42" fill="#231a72"/>
  <text x="120" y="294" font-family="Arial, sans-serif" font-size="18" font-weight="700" fill="#ffffff">ORCAMENTO No</text>
  <text x="430" y="294" font-family="Arial, sans-serif" font-size="18" font-weight="700" fill="#ffffff">EMITIDO EM</text>
  <text x="710" y="294" font-family="Arial, sans-serif" font-size="18" font-weight="700" fill="#ffffff">VALIDO ATE</text>
  <text x="120" y="348" font-family="Arial, sans-serif" font-size="25" font-weight="700" fill="#1a1a2e">${escapeXml(numero)}</text>
  <text x="430" y="348" font-family="Arial, sans-serif" font-size="25" fill="#1a1a2e">${escapeXml(emissao)}</text>
  <text x="710" y="348" font-family="Arial, sans-serif" font-size="25" font-weight="700" fill="#e8892a">${escapeXml(validade)}</text>

  <rect x="95" y="402" width="890" height="176" fill="#ffffff" stroke="#dde3ec"/>
  <rect x="95" y="402" width="445" height="42" fill="#231a72"/>
  <rect x="540" y="402" width="445" height="42" fill="#231a72"/>
  <text x="120" y="430" font-family="Arial, sans-serif" font-size="18" font-weight="700" fill="#ffffff">CLIENTE</text>
  <text x="565" y="430" font-family="Arial, sans-serif" font-size="18" font-weight="700" fill="#ffffff">TELEFONE</text>
  <text x="120" y="492" font-family="Arial, sans-serif" font-size="28" font-weight="700" fill="#1a1a2e">${escapeXml(nome)}</text>
  <text x="565" y="492" font-family="Arial, sans-serif" font-size="25" fill="#1a1a2e">${escapeXml(telefone)}</text>
  <rect x="95" y="526" width="890" height="42" fill="#231a72"/>
  <text x="120" y="554" font-family="Arial, sans-serif" font-size="18" font-weight="700" fill="#ffffff">ENDERECO</text>
  <text x="120" y="610" font-family="Arial, sans-serif" font-size="23" fill="#1a1a2e">${escapeXml(endereco)}</text>

  <text x="95" y="675" font-family="Arial, sans-serif" font-size="22" font-weight="700" fill="#231a72">SERVICO</text>
  <rect x="95" y="700" width="890" height="248" fill="#ffffff" stroke="#dde3ec"/>
  <rect x="95" y="700" width="890" height="48" fill="#231a72"/>
  <text x="120" y="731" font-family="Arial, sans-serif" font-size="17" font-weight="700" fill="#ffffff">DESCRICAO DO SERVICO</text>
  <text x="585" y="731" font-family="Arial, sans-serif" font-size="17" font-weight="700" fill="#ffffff">QTD</text>
  <text x="675" y="731" font-family="Arial, sans-serif" font-size="17" font-weight="700" fill="#ffffff">UNID.</text>
  <text x="760" y="731" font-family="Arial, sans-serif" font-size="17" font-weight="700" fill="#ffffff">PRECO/M2</text>
  <text x="900" y="731" font-family="Arial, sans-serif" font-size="17" font-weight="700" fill="#ffffff">TOTAL</text>
  <text x="120" y="795" font-family="Georgia, serif" font-size="24" font-weight="700" fill="#1a1a2e">${escapeXml(servico[0])}</text>
  <text x="120" y="837" font-family="Arial, sans-serif" font-size="21" fill="#1a1a2e">${escapeXml(servico[1])}</text>
  <text x="120" y="879" font-family="Arial, sans-serif" font-size="21" fill="#1a1a2e">${escapeXml(servico[2])}</text>
  <text x="585" y="820" font-family="Arial, sans-serif" font-size="23" fill="#1a1a2e">${escapeXml(area.toLocaleString("pt-BR", { maximumFractionDigits: 2 }))}</text>
  <text x="685" y="820" font-family="Arial, sans-serif" font-size="23" fill="#1a1a2e">m2</text>
  <text x="770" y="820" font-family="Arial, sans-serif" font-size="23" fill="#1a1a2e">${escapeXml(formatMoney(precoM2))}</text>
  <text x="880" y="820" font-family="Arial, sans-serif" font-size="23" font-weight="700" fill="#1a1a2e">${escapeXml(formatMoney(total))}</text>

  <rect x="95" y="986" width="890" height="118" fill="#ffffff" stroke="#231a72" stroke-width="3"/>
  <text x="125" y="1032" font-family="Arial, sans-serif" font-size="20" font-weight="700" fill="#6b7280">TOTAL DO PROJETO</text>
  <text x="125" y="1084" font-family="Georgia, serif" font-size="48" font-weight="700" fill="#231a72">${escapeXml(formatMoney(total))}</text>

  <text x="95" y="1165" font-family="Arial, sans-serif" font-size="22" font-weight="700" fill="#231a72">CONDICOES DE PAGAMENTO</text>
  <rect x="95" y="1190" width="890" height="150" fill="#ffffff" stroke="#dde3ec"/>
  <rect x="95" y="1190" width="890" height="44" fill="#231a72"/>
  <text x="120" y="1219" font-family="Arial, sans-serif" font-size="17" font-weight="700" fill="#ffffff">A VISTA - PIX</text>
  <text x="380" y="1219" font-family="Arial, sans-serif" font-size="17" font-weight="700" fill="#ffffff">PARCELADO</text>
  <text x="660" y="1219" font-family="Arial, sans-serif" font-size="17" font-weight="700" fill="#ffffff">ENTRADA + CONCLUSAO</text>
  <text x="120" y="1290" font-family="Georgia, serif" font-size="31" font-weight="700" fill="#16803c">${escapeXml(formatMoney(total))}</text>
  <text x="380" y="1270" font-family="Arial, sans-serif" font-size="18" fill="#1a1a2e">Ate 12x no cartao</text>
  <text x="380" y="1302" font-family="Arial, sans-serif" font-size="18" fill="#1a1a2e">com taxa da operadora.</text>
  <text x="660" y="1270" font-family="Arial, sans-serif" font-size="18" fill="#1a1a2e">60% de sinal: ${escapeXml(formatMoney(entrada))}</text>
  <text x="660" y="1302" font-family="Arial, sans-serif" font-size="18" fill="#1a1a2e">restante no termino.</text>

  <line x1="150" y1="1400" x2="430" y2="1400" stroke="#1a1a2e" stroke-width="2"/>
  <line x1="650" y1="1400" x2="930" y2="1400" stroke="#1a1a2e" stroke-width="2"/>
  <text x="170" y="1433" font-family="Arial, sans-serif" font-size="18" fill="#1a1a2e">A.L.A DECOR Pisos Laminados e Vinilicos</text>
  <text x="745" y="1433" font-family="Arial, sans-serif" font-size="18" fill="#1a1a2e">${escapeXml(nome)}</text>

  <rect x="60" y="1474" width="960" height="54" fill="#231a72"/>
  <text x="92" y="1508" font-family="Arial, sans-serif" font-size="18" fill="#ffffff">A.L.A DECOR - Pisos Vinilicos e Laminados - (11) 97780-3209 - @a.l.a_decoracoes</text>
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

 if (pathname === "/api/crm/gerar-orcamento") {
  const result = buildBudget(payload);

  if (result.status === "precisa_dados") {
    return json({
      success: false,
      error: result.mensagem
    }, 400);
  }

  return json({
    success: true,
    image_url: buildBudgetImageUrl(requestUrl, payload),
    orcamento: result
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
