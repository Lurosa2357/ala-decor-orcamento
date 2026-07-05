# Webhooks A.L.A Decor

Depois de publicado no Cloudflare, use estas rotas:

- `GET /api/webhook` - testa se o webhook esta online.
- `POST /api/webhook` - recebe qualquer evento generico.
- `POST /api/webhook/lionchat` - rota sugerida para eventos do LionChat.
- `POST /api/lionchat/webhook` - alias para eventos do LionChat.
- `POST /api/crm/orcamento` - recebe dados de orcamento.
- `POST /api/crm/contrato` - recebe dados de contrato.

## Seguranca

Configure um segredo no Cloudflare:

```bash
wrangler secret put WEBHOOK_SECRET
```

Quando `WEBHOOK_SECRET` estiver ativo, envie o header:

```text
x-webhook-secret: seu-segredo
```

## Encaminhar para outro webhook

Se quiser que o Worker receba e repasse para outro CRM, configure:

```bash
wrangler secret put FORWARD_WEBHOOK_URL
```

Opcionalmente:

```bash
wrangler secret put FORWARD_WEBHOOK_SECRET
```

## Exemplo de payload

```json
{
  "source": "aladecor",
  "tipo": "orcamento",
  "cliente": "Nome do cliente",
  "telefone": "11999999999",
  "endereco": "Rua exemplo, 123",
  "valor_total": 3995,
  "mensagem": "Texto que sera enviado ao cliente"
}
```
