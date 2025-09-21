# NexShop Identity SDK - Uso e Configuracao

SDK antifraude para validacao de identidade com baixo atrito. Backend em Node.js (Express) e frontend React via CDN (sem bundler). Codigo em JavaScript.

## Visao geral
- Coleta sinais de ambiente do cliente (fingerprint passivo)
- Sinais coletados:
  - IP (derivado no backend via cabecalhos/req.ip)
  - Language do navegador (frontend)
  - User-Agent do navegador (frontend e cabeçalho HTTP)
  - Resolucao de tela (frontend)
  - Timezone offset (frontend)
- Opcional: consulta AbuseIPDB por IP
- Calcula risk score (0..100) e retorna status: allow | review | deny
- Sugere desafio quando necessario: OTP, Email ou Biometria (face)
- Logs em JSON e NDJSON para integracao com ferramentas (Fluent Bit / Logstash)

## Estrutura do projeto
- backend/
  - src/
    - server.js
    - sdkMiddleware.js
    - riskEngine.js
    - services/abuseIpdb.js
    - loggers/jsonLogger.js
    - challenges/
      - otp.js, email.js, biometric.js, store.js
  - package.json
- frontend/
  - index.html
  - app.jsx
  - src/sdk/identitySdk.js
- logs/ (gerado em runtime pelo backend)

## Como rodar
1) Backend
```
cd backend
npm i
npm run dev
```
Servidor em http://localhost:4000

2) Frontend (estatico)
- Abra `frontend/index.html` diretamente no navegador (duplo clique)
- ou sirva a pasta `frontend/` com um servidor estatico simples (ex.: extensao Live Server do VSCode)

## Configuracao (.env no backend)
```
PORT=4000
ALLOW_THRESHOLD=70
REVIEW_THRESHOLD=50

# Pesos de sinais
WEIGHT_IP=20
WEIGHT_UA=25
WEIGHT_TZ=15
WEIGHT_LANG=15
WEIGHT_RES=10
WEIGHT_ABUSE=30

# AbuseIPDB (opcional)
ABUSEIPDB_ENABLED=false
ABUSEIPDB_API_KEY=
ABUSEIPDB_DAYS=30
ABUSEIPDB_MALICIOUS_THRESHOLD=75

# Desafios disponiveis
CHALLENGES=OTP,EMAIL,BIOMETRIC

# SMTP (para desafio de Email)
SMTP_HOST=
SMTP_PORT=587
SMTP_SECURE=false
SMTP_USER=
SMTP_PASS=
SMTP_FROM=
```

## API
### POST /identity/verify
Body (exemplo) - campos do frontend:
```
{
  "language": "pt-BR",
  "userAgent": "Mozilla/5.0 ...",
  "timezoneOffset": 180,
  "screen": {"width": 1920, "height": 1080, "pixelRatio": 1},
  "sessionMeta": {"referrer": "", "url": "http://localhost:5173", "visibility": "visible"}
}
```
Resposta:
```
{
  "status": "allow|review|deny",
  "score": 0-100,
  "reasons": ["ua_headless", "abuseipdb_warning"],
  "suggestedChallenge": "OTP|EMAIL|BIOMETRIC|null",
  "challengeRequired": true|false,
  "thresholds": {"allow": 70, "review": 50},
  "ip": "203.0.113.5",
  "tookMs": 12
}
```

### POST /identity/challenge/initiate
Body:
- `{ "type": "OTP" }`
- `{ "type": "EMAIL", "email": "usuario@exemplo.com" }`
- `{ "type": "BIOMETRIC", "referenceEmbedding": [ ... ] }`

### POST /identity/challenge/verify
Body:
- OTP/Email: `{ "type": "OTP|EMAIL", "challengeId": "...", "code": "123456" }`
- Biometria: `{ "type": "BIOMETRIC", "challengeId": "...", "embedding": [ ... ] }`

### GET /identity/config
Retorna configuracao atual (limiares, pesos, regras adicionais).

### PUT /identity/config
Atualiza configuracao em runtime. Exemplo:
```
{
  "allowThreshold": 75,
  "reviewThreshold": 55,
  "riskWeights": { "userAgent": 30 },
  "extraFieldRules": [
    { "field": "tabNotFocused", "type": "boolean", "weight": 5 },
    { "field": "failedLoginCount", "type": "numeric_range", "min": 3, "max": 99, "weight": 15 }
  ]
}
```

## Risk score e campos extras
- Sinais base: IP (backend), userAgent (frontend), language (frontend), timezoneOffset (frontend), resolucao (frontend), AbuseIPDB (backend)
- Desafios NAO alteram o score; apenas sao exigidos quando score < minimo ou IP for malicioso (AbuseIPDB)
- Para adicionar novos sinais: envie `extraSignals` no body do verify e defina regras em `extraFieldRules` via PUT /identity/config

## AbuseIPDB
- Habilite com `ABUSEIPDB_ENABLED=true` e defina `ABUSEIPDB_API_KEY`
- Cada IP coletado e consultado
- Se malicioso (acima do limiar definido), a resposta exige desafio (challengeRequired = true) e no minimo `review`
- Logs dedicados sao gravados (ver secao de logs)

## Desafios (OTP, Email, Biometria)
- OTP: usa otplib (TOTP). Opcionalmente, QR para cadastro de segredo. Verifica codigo de 6 digitos
- Email: envia codigo por email (nodemailer)
- Biometria: captura de embedding facial no frontend (consentimento), compara com similaridade de cosseno

## Logs e integracao com SIEM
Arquivos gerados em `backend/logs`:
- Acessos: `acess-<datahora>.json` e `access.ndjson`
- AbuseIPDB: `apubeipdb-<datahora>.json` e `abuseipdb.ndjson`
- Desafios: `challenge-<datahora>.json` e `challenge.ndjson`

Exemplo Fluent Bit (minimo):
```
[INPUT]
    Name tail
    Path backend/logs/*.ndjson
    Parser json
    Tag nexshop.identity

[OUTPUT]
    Name stdout
    Match *
```

Exemplo Logstash (minimo):
```
input {
  file {
    path => "backend/logs/*.ndjson"
    start_position => "beginning"
    sincedb_path => "/dev/null"
  }
}
filter {
  json { source => "message" }
}
output {
  stdout { codec => rubydebug }
}
```

## Frontend estatico
- `frontend/index.html` carrega React e Babel via CDN e o SDK global em `src/sdk/identitySdk.js`
- O app exemplo esta em `frontend/app.jsx`
- Biometria: quando habilitada, os modelos face-api sao carregados de CDN publico por padrao

## Seguranca e privacidade
- Coleta passiva por padrao (sem interacao)
- Para biometria, obtenha consentimento explicito
- Avalie LGPD/privacidade conforme seu caso de uso

## Suporte
- Expanda regras no arquivo `backend/src/riskEngine.js`
- Ajuste pesos e limiares via `.env` ou via API de configuracao
- Integre os logs NDJSON em seu pipeline de observabilidade


