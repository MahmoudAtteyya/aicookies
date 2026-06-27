<div align="center">

# 🍪 AI Proxy Gateway

### A production-grade OpenAI-compatible API gateway with multi-provider support, smart key rotation, Claude cookie orchestration, and a professional management dashboard.

[![Version](https://img.shields.io/badge/version-5.1.0-7c3aed?style=flat-square)](https://github.com/MahmoudAtteyya/aicookies)
[![Python](https://img.shields.io/badge/Python-3.13+-3776AB?style=flat-square&logo=python&logoColor=white)](https://python.org)
[![Flask](https://img.shields.io/badge/Flask-3.1+-000000?style=flat-square&logo=flask&logoColor=white)](https://flask.palletsprojects.com)
[![Docker](https://img.shields.io/badge/Docker-Ready-2496ED?style=flat-square&logo=docker&logoColor=white)](https://docker.com)
[![License](https://img.shields.io/badge/License-MIT-green?style=flat-square)](LICENSE)
[![Status](https://img.shields.io/badge/Status-Production%20Ready-3fb950?style=flat-square)](https://aicookies.elliaa.com)

**Live API:** `https://aicookies.elliaa.com/v1/chat/completions`  
**Dashboard:** `https://aicookies.elliaa.com`  
**Docs:** `https://aicookies.elliaa.com/docs`

</div>

---

## 📖 Table of Contents

- [Overview](#-overview)
- [Key Features](#-key-features)
- [Architecture](#-architecture)
- [Available Models](#-available-models-15-total)
- [API Reference](#-api-reference)
- [Authentication](#-authentication)
- [Quick Start](#-quick-start)
- [Production Resilience Layer](#-production-resilience-layer)
- [Configuration](#️-configuration-environment-variables)
- [Streaming (SSE)](#-streaming-sse)
- [Function Calling](#-function-calling-path-b-emulation)
- [Native Web Search](#-native-web-search)
- [Claude Cookie Proxy](#-claude-cookie-proxy)
- [Smart Key Rotation](#-smart-key-rotation)
- [Security Layer](#-security-layer)
- [Reliability Layer](#-reliability-layer)
- [Frontend Dashboard](#-frontend-dashboard)
- [Deployment](#-deployment)
- [Configuration](#-configuration-environment-variables)
- [Playwright Auto-Capture](#-playwright-auto-capture-laptop)
- [Troubleshooting](#-troubleshooting)
- [Project Structure](#-project-structure)
- [Contributing](#-contributing)
- [License](#-license)

---

## 🎯 Overview

AI Proxy Gateway is a self-hosted, OpenAI-compatible API gateway that aggregates **15 AI models from 5 providers** behind a single endpoint. It solves three critical problems:

1. **Unified API**: One endpoint, one auth token, one SDK — regardless of which provider the model runs on. Clients using the standard OpenAI SDK can switch between Claude, Mistral, Cohere, SambaNova, and Fireworks models without changing a single line of code.

2. **Key Rotation & Orchestration**: Automatically rotates through multiple API keys per provider using a least-used-first strategy. Claude cookies are orchestrated with affinity tracking, tier-aware selection, cooldown timers, and quarantine states.

3. **Claude.ai Cookie Proxy**: Access Claude.ai (Sonnet 4, Opus 4, Haiku 4.5, Fable 5) through browser cookies — no Anthropic API key required. Uses `curl_cffi` with TLS fingerprint impersonation (`chrome131`) to bypass Cloudflare's JA3 fingerprint validation, IPRoyal residential proxies for IP rotation, and a natural prompt middleware to format API messages as conversation text.

### Why This Exists

Commercial AI API providers each have their own SDKs, authentication schemes, rate limits, and billing models. Managing multiple providers in a single application requires writing provider-specific code for each one. AI Proxy Gateway abstracts all of this behind the standard OpenAI Chat Completions API — you send one request, the gateway handles provider routing, key selection, retry logic, rate limiting, and response normalization.

---

## ✨ Key Features

| Feature | Description |
|---------|-------------|
| **OpenAI-Compatible API** | Drop-in replacement for OpenAI's `/v1/chat/completions` endpoint. Works with any OpenAI SDK (Python, JavaScript, Go, etc.) |
| **15 Models, 5 Providers** | Claude (cookie), Mistral AI, Cohere, SambaNova, Fireworks — all behind one URL |
| **Smart Key Rotation** | Least-used-first key selection, automatic cooldown on rate limits (429), permanent dead-marking on auth failures (401/403) |
| **Claude Cookie Orchestration** | Affinity tracking (multi-turn pinned to same cookie), tier-aware selection (free/pro/max), availability states (active/parked/quarantined), thread-safe with `RLock` |
| **curl_cffi TLS Impersonation** | Bypasses Cloudflare's JA3 fingerprint validation by impersonating Chrome 131's exact TLS fingerprint |
| **Natural Prompt Middleware** | Converts OpenAI-format messages into natural conversation text — no external API calls, zero latency overhead, preserves multi-turn context and system prompts |
| **Function Calling (Path B)** | Emulates OpenAI function calling via XML injection for Claude — supports `tools` array, `tool_choice`, and tool result rendering |
| **Native Web Search** | Claude.ai free-tier accounts can do real-time web search via `tools` array with `web_search_v0` type |
| **Artifact Compatibility** | Transforms Claude's proprietary `<antArtifact>` XML into standard Markdown code blocks (15-type mapping) |
| **Fernet Cookie Encryption** | At-rest encryption for stored cookies using Python `cryptography.Fernet` — falls back to plaintext if no key configured |
| **Token Bucket Rate Limiting** | 60 req/min per IP with 1 token/sec refill, returns 429 with `Retry-After` header |
| **Retry with Exponential Backoff** | Automatic retries on 429/502/503/504/529 with jitter, respects `Retry-After` headers |
| **Proxy Blacklist** | Auto-blacklist residential proxy IPs after 3 failures for 5 minutes |
| **Server-Sent Events (SSE)** | Real-time streaming with Anthropic→OpenAI format transformation, per-chunk tool artifact filtering |
| **Production WSGI** | gunicorn with 2 workers and 120s timeout — not Flask dev server |
| **SQLite with WAL Mode** | Write-Ahead Logging for concurrent read/write access, `busy_timeout=5000ms` to prevent lock errors |
| **CSRF Protection** | All POST forms require a CSRF token via Jinja context processor |
| **Login Rate Limiting** | 5 attempts per 15 minutes per IP, automatic lockout |
| **Management Dashboard** | Web UI for managing API keys, Claude cookies, proxy tokens, and viewing request stats |
| **CORS Support** | Permissive CORS headers — works from any frontend |
| **Health Endpoint** | `/v1/health` returns status, model count, active keys, Claude orchestration state |
| **Cross-Provider Fallback** | When ALL keys for a provider are exhausted, automatically tries a similar model from another provider (e.g. Fireworks→SambaNova→Mistral). Claude falls back to GLM-5.2 reasoning model |
| **Mid-Stream Continuation** | If a Claude session fails mid-response (timeout, 429), partial text is captured and the next session continues from exactly where it left off — no repetition, seamless to the client |
| **User-Friendly Errors** | 9 typed error responses (RATE_LIMITED, ALL_KEYS_EXHAUSTED, CLAUDE_ALL_SESSIONS_BUSY, TIMEOUT, etc.) with title, message, suggestion, and retry_after_ms. Streaming errors sent as SSE events |
| **180s Claude Timeout** | Extended timeout for reasoning models that take longer to think before responding |
| **Custom Endpoints** | Create virtual API endpoints (`/v1/{slug}/chat/completions`) with forced system prompts, model pinning, and parameter overrides — full developer control without touching the base API |

---

## 🏗 Architecture

```
┌─────────────────────────────────────────────────────────────────────┐
│                         Client (OpenAI SDK)                          │
│                  POST /v1/chat/completions                           │
└──────────────────────────┬──────────────────────────────────────────┘
                           │
                           ▼
┌─────────────────────────────────────────────────────────────────────┐
│                    AI Proxy Gateway (Flask + gunicorn)              │
│  ┌─────────┐ ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌───────────┐  │
│  │  Auth   │ │  Rate    │ │  Model   │ │  CORS    │ │  CSRF     │  │
│  │ Check   │ │  Limiter │ │  Router  │ │ Headers  │ │ Protect   │  │
│  └─────────┘ └──────────┘ └────┬─────┘ └──────────┘ └───────────┘  │
│                                │                                     │
│         ┌──────────────────────┼──────────────────────┐             │
│         │                      │                      │             │
│         ▼                      ▼                      ▼             │
│  ┌──────────────┐    ┌──────────────┐     ┌──────────────────┐     │
│  │  Direct API  │    │  Claude      │     │  Retry Engine    │     │
│  │  Providers   │    │  Cookie      │     │  (Exponential    │     │
│  │  (httpx)     │    │  Proxy       │     │   Backoff)       │     │
│  │              │    │  (curl_cffi) │     │                  │     │
│  │ • Mistral    │    │              │     │  Status codes:   │     │
│  │ • Cohere     │    │  TLS: chrome │     │  429,502,503,    │     │
│  │ • SambaNova  │    │  131         │     │  504,529         │     │
│  │ • Fireworks  │    │              │     │                  │     │
│  └──────┬───────┘    │  Proxy:      │     └──────────────────┘     │
│         │            │  IPRoyal     │                              │
│         │            │  Residential │                              │
│         │            └──────┬───────┘                              │
└─────────┼───────────────────┼──────────────────────────────────────┘
          │                   │
          ▼                   ▼
┌──────────────────┐  ┌──────────────────────────────────────────────┐
│  Provider APIs   │  │  claude.ai (via Cloudflare)                  │
│  • api.mistral   │  │  • Fernet-encrypted cookie store             │
│  • api.cohere    │  │  • Affinity tracking (SHA-256 fingerprint)   │
│  • api.sambanova │  │  • Tier system (free/pro/max)               │
│  • api.fireworks │  │  • Availability states: active/parked/dead  │
│                  │  │  • Cooldown timer (5 min on 429)            │
└──────────────────┘  └──────────────────────────────────────────────┘
          │
          ▼
┌─────────────────────────────────────────────────────────────────────┐
│                    SQLite (WAL mode, busy_timeout=5000)             │
│  Tables: api_providers, api_keys, cookie_files, cookies,            │
│          proxy_api_keys, proxy_requests                              │
└─────────────────────────────────────────────────────────────────────┘
```

### Request Flow

1. **Client** sends a standard OpenAI Chat Completions request with `model` slug
2. **Auth Check**: Bearer token validated against SHA-256 hashes in `proxy_api_keys` table
3. **Rate Limiter**: Token bucket algorithm (60 req/min, 1 token/sec refill)
4. **Model Router**: Looks up `MODELS` dict → determines provider (`claude` / `mistral` / `cohere` / `sambanova` / `fireworks`)
5. **Provider Handler**:
   - **Direct providers** (Mistral, Cohere, SambaNova, Fireworks): Uses `httpx` to call provider API with least-used-first key rotation
   - **Claude**: Uses `curl_cffi` with `impersonate="chrome131"` + IPRoyal residential proxy + browser cookies + natural prompt middleware
6. **Response Normalization**: All responses transformed to OpenAI format (including `usage`, `finish_reason`, streaming chunks)
7. **Retry Engine**: On 429/502/503/504/529 → exponential backoff with jitter, respects `Retry-After`
8. **Key Management**: Successful key → `usage_count++`; 429 → cooldown; 401/403 → dead-marked

---

## 🤖 Available Models (15 total)

### ⚡ Direct Response Models (12)

| Slug | Provider | Real Model | Context | Description |
|------|----------|------------|---------|-------------|
| `claude-sonnet-4-6` | 🍪 Claude | claude-sonnet-4-6 | 200K | Claude Sonnet 4 via cookie proxy |
| `mistral-small` | Mistral AI | mistral-small-latest | 32K | Fast, efficient general-purpose |
| `mistral-medium` | Mistral AI | mistral-medium-latest | 32K | Balanced quality and speed |
| `mistral-nemo` | Mistral AI | open-mistral-nemo | 128K | Open-source 12B model |
| `codestral` | Mistral AI | codestral-latest | 256K | Code generation specialist |
| `ministral-8b` | Mistral AI | ministral-8b-latest | 128K | Lightweight 8B model |
| `command-a` | Cohere | command-a-03-2025 | 256K | Latest flagship model |
| `command-r7b` | Cohere | command-r7b-12-2024 | 128K | Fast & capable |
| `command-r-plus` | Cohere | command-r-plus-08-2024 | 128K | Most powerful Cohere model |
| `llama-3.3-70b` | SambaNova | Meta-Llama-3.3-70B-Instruct | 131K | Powerful open model |
| `kimi-k2p7-code` | Fireworks | kimi-k2p7-code | 32K | Code generation specialist |

### 🧠 Reasoning Models (3)

| Slug | Provider | Real Model | Context | Description |
|------|----------|------------|---------|-------------|
| `glm-5p2` | Fireworks | accounts/fireworks/models/glm-5p2 | 131K | General reasoning with thinking |
| `qwen3p7-plus` | Fireworks | accounts/fireworks/models/qwen3p7-plus | 4K | Multimodal reasoning |
| `deepseek-v4-pro` | Fireworks | accounts/fireworks/models/deepseek-v4-pro | 131K | Deep reasoning specialist |

> ⚠️ **Reasoning models** return a `reasoning_content` field alongside `content`. Set `max_tokens ≥ 500` to avoid truncated thinking.

---

## 📡 API Reference

### Base URL

```
https://aicookies.elliaa.com
```

### Chat Completions

```http
POST /v1/chat/completions
Authorization: Bearer YOUR_API_KEY
Content-Type: application/json
```

**Request body:**

```json
{
  "model": "mistral-small",
  "messages": [
    {"role": "system", "content": "You are a helpful assistant."},
    {"role": "user", "content": "Hello!"}
  ],
  "stream": false,
  "max_tokens": 1024,
  "temperature": 0.7
}
```

**Response (non-streaming):**

```json
{
  "id": "chatcmpl-xxx",
  "object": "chat.completion",
  "created": 1782593895,
  "model": "mistral-small-latest",
  "choices": [
    {
      "index": 0,
      "message": {
        "role": "assistant",
        "content": "Hello! How can I help you?"
      },
      "finish_reason": "stop"
    }
  ],
  "usage": {
    "prompt_tokens": 19,
    "completion_tokens": 7,
    "total_tokens": 26
  }
}
```

### Model-Specific Endpoint

```http
POST /v1/{model_slug}/chat/completions
```

### List Models

```http
GET /v1/models
Authorization: Bearer YOUR_API_KEY
```

### Health Check (no auth)

```http
GET /v1/health
```

**Response:**

```json
{
  "status": "healthy",
  "version": "3.0.0",
  "models_available": 14,
  "active_api_keys": 13,
  "claude_sessions": 5,
  "claude_orchestration": {
    "active": 5,
    "affinity_pins": 1,
    "parked": 0,
    "quarantined": 0
  },
  "proxy_provider": "IPRoyal",
  "proxy_blacklist": [],
  "timestamp": "2026-06-27T20:59:50.552382+00:00"
}
```

### Management Endpoints (require login session)

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/` | Dashboard — overview of keys, cookies, stats |
| `GET` | `/keys` | API Keys manager — add/delete/toggle keys |
| `POST` | `/keys` | Add a new API key |
| `GET` | `/tokens` | Token management — create/pause/revoke proxy tokens |
| `POST` | `/tokens/create` | Create a new proxy API token |
| `POST` | `/tokens/pause/<id>` | Pause a token |
| `POST` | `/tokens/activate/<id>` | Activate a paused token |
| `POST` | `/tokens/revoke/<id>` | Revoke a token permanently |
| `GET` | `/upload` | Upload Claude cookie file (Netscape format) |
| `POST` | `/upload` | Process uploaded cookie file |
| `GET` | `/cookies/<id>` | View parsed cookies for a file |
| `POST` | `/delete-cookie/<id>` | Delete a cookie file |
| `POST` | `/delete-key/<id>` | Delete an API key |
| `POST` | `/toggle-key/<id>` | Toggle key active/inactive |
| `GET` | `/docs` | Full API documentation page |
| `GET` | `/docs.md` | Download documentation as Markdown |

### API Endpoints (Bearer auth or login session)

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/api/cookies?platform=claude` | List cookie files |
| `GET` | `/api/cookies/raw/<id>` | Get raw cookie text |
| `GET` | `/api/cookies/latest?platform=claude` | Get most recent cookie file |
| `GET` | `/api/keys?provider=<slug>` | List API keys for a provider |
| `POST` | `/api/keys` | Add a key programmatically |
| `GET` | `/api/keys/next/<provider>` | Get least-used key for a provider |
| `POST` | `/api/keys/mark-rate-limited/<id>` | Mark a key as rate-limited |
| `POST` | `/api/keys/revive` | Revive all dead keys |
| `POST` | `/api/keys/revive/<id>` | Revive a specific dead key |
| `POST` | `/api/keys/reset-usage/<provider>` | Reset usage counters for a provider |
| `GET` | `/api/providers` | List all providers with key counts |
| `GET` | `/api/models` | List all available models |
| `GET` | `/api/stats` | Request statistics + Claude token state |

---

## 🔐 Authentication

### Proxy API Key

All `/v1/*` endpoints require a Bearer token:

```bash
Authorization: Bearer sk-aic-xxxxxxxxxxxxxxxxxxxxxxxx
```

Keys are minted via the `/tokens` dashboard or `/generate-key` admin endpoint. The raw key is shown once at creation time — only the SHA-256 hash is stored in the database.

**Key format:** `sk-aic-` prefix + `token_urlsafe(32)` (43 characters of URL-safe base64)

**Validation:** SHA-256 hash comparison using `hmac.compare_digest` (constant-time to prevent timing attacks)

### Dashboard Login

The management dashboard (`/`, `/keys`, `/tokens`, `/upload`) requires a login session:

- **Login URL:** `/login`
- **Credentials:** Configured via `AUTH_USERNAME` and `AUTH_PASSWORD_HASH` environment variables
- **Session timeout:** 30 minutes (configurable via `PERMANENT_SESSION_LIFETIME`)
- **Rate limiting:** 5 login attempts per 15 minutes per IP

---

## 🚀 Quick Start

### cURL

```bash
curl -X POST https://aicookies.elliaa.com/v1/chat/completions \
  -H "Authorization: Bearer YOUR_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "model": "mistral-small",
    "messages": [{"role": "user", "content": "Say hello in Arabic"}]
  }'
```

### Python (OpenAI SDK)

```python
from openai import OpenAI

client = OpenAI(
    base_url="https://aicookies.elliaa.com/v1",
    api_key="YOUR_API_KEY"
)

response = client.chat.completions.create(
    model="claude-sonnet-4-6",
    messages=[{"role": "user", "content": "Write a haiku about coding"}]
)

print(response.choices[0].message.content)
```

### JavaScript / TypeScript (OpenAI SDK)

```javascript
import OpenAI from "openai";

const client = new OpenAI({
  baseURL: "https://aicookies.elliaa.com/v1",
  apiKey: "YOUR_API_KEY",
});

const response = await client.chat.completions.create({
  model: "glm-5p2",
  messages: [{ role: "user", content: "Explain recursion in 3 sentences" }],
  max_tokens: 500,
});

console.log(response.choices[0].message.content);
```

### Python (httpx)

```python
import httpx

response = httpx.post(
    "https://aicookies.elliaa.com/v1/chat/completions",
    headers={
        "Authorization": "Bearer YOUR_API_KEY",
        "Content-Type": "application/json",
    },
    json={
        "model": "mistral-small",
        "messages": [{"role": "user", "content": "Hello!"}],
    },
    timeout=60.0,
)

print(response.json()["choices"][0]["message"]["content"])
```

---

## 📡 Streaming (SSE)

Add `"stream": true` to the request body for real-time token streaming. The response comes as Server-Sent Events with `data:` lines, terminated by `data: [DONE]`.

```bash
curl -N -X POST https://aicookies.elliaa.com/v1/chat/completions \
  -H "Authorization: Bearer YOUR_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "model": "mistral-small",
    "stream": true,
    "messages": [{"role": "user", "content": "Count from 1 to 10"}]
  }'
```

**Output format:**

```
data: {"id":"chatcmpl-xxx","object":"chat.completion.chunk","choices":[{"index":0,"delta":{"role":"assistant","content":""},"finish_reason":null}]}

data: {"id":"chatcmpl-xxx","object":"chat.completion.chunk","choices":[{"index":0,"delta":{"content":"1"},"finish_reason":null}]}

data: {"id":"chatcmpl-xxx","object":"chat.completion.chunk","choices":[{"index":0,"delta":{"content":", 2"},"finish_reason":null}]}

...

data: {"id":"chatcmpl-xxx","object":"chat.completion.chunk","choices":[{"index":0,"delta":{},"finish_reason":"stop"}]}

data: [DONE]
```

### Claude Streaming: Anthropic → OpenAI Transformation

Claude.ai returns streaming chunks in Anthropic's proprietary format. The gateway's `transform_claude_stream()` function:

1. Parses each `data:` line from Claude's SSE response
2. Extracts text from **both formats**: legacy `completion` field AND new `content_block_delta`/`text_delta` (used when tools/web search are enabled)
3. Extracts `stop_reason` from both `stop_reason` field AND `message_delta` event
4. Filters tool artifacts per-chunk (`<function_calls>`, `<invoke>` XML stripped)
5. Strips `messageLimit` objects (huge, serve no purpose — saves 80%+ bandwidth)
6. Adds `[DONE]` terminal marker
7. Uses `yield from` for true streaming (not buffer-and-chunk)

**stop_reason mapping:**

| Anthropic | OpenAI |
|-----------|--------|
| `end_turn` | `stop` |
| `stop_sequence` | `stop` |
| `max_tokens` | `length` |
| `tool_use` | `tool_calls` |
| `null` | `null` |

---

## 🛠 Function Calling (Path B Emulation)

The gateway emulates OpenAI function calling for Claude via XML injection:

1. **`_render_tools_preamble()`** injects tool definitions as a natural preamble telling Claude what tools exist and how to call them via `<function_calls><invoke name="...">` XML
2. **`tool_choice`** support: `"none"`, `"required"`, `{"function": {"name": "..."}}`
3. **`parse_tool_calls_from_response()`** extracts tool calls from `<function_calls><invoke>` XML (tolerant: also handles ```json fences)
4. Response includes `tool_calls` array in OpenAI format with `finish_reason: "tool_calls"`
5. Tool XML is stripped from text content via `filter_tool_artifacts()`

**Tool History Rendering:** Assistant `tool_calls` → `[I called name(args)]`, `role: "tool"` messages → `[Tool result for id]: content`. This enables multi-turn tool conversations.

```python
response = client.chat.completions.create(
    model="claude-sonnet-4-6",
    messages=[{"role": "user", "content": "What's the weather in Cairo?"}],
    tools=[{
        "type": "function",
        "function": {
            "name": "get_weather",
            "description": "Get current weather for a city",
            "parameters": {
                "type": "object",
                "properties": {"city": {"type": "string"}},
                "required": ["city"]
            }
        }
    }],
)
```

---

## 🔍 Native Web Search

Claude.ai free-tier accounts can perform real-time web search. The completion payload includes a `tools` array with `{"type": "web_search_v0", "name": "web_search"}` alongside additional required fields:

```json
{
  "prompt": "...",
  "timezone": "Africa/Cairo",
  "locale": "en-US",
  "rendering_mode": "messages",
  "attachments": [],
  "files": [],
  "sync_sources": [],
  "personalized_styles": [],
  "tools": [{"type": "web_search_v0", "name": "web_search"}]
}
```

Claude executes the search server-side and returns results in `tool_use`/`tool_result` SSE blocks. The gateway extracts only `text_delta` content — tool blocks are silently dropped, so users see only the final answer with real search data.

> **Verified live:** Gold price $4,085/oz, Bitcoin $60,136 (June 27, 2026).

---

## 🍪 Claude Cookie Proxy

Claude.ai is accessed through browser cookies, not API keys. This enables using Claude Sonnet 4, Opus 4, Haiku 4.5, and Fable 5 without an Anthropic API key.

### How It Works

1. **Cookie Capture**: User logs into claude.ai in a real browser (Chrome). Cookies are exported in Netscape format (including `sessionKey`, `cf_clearance`, `__cf_bm`, and all other cookies).
2. **Cookie Upload**: Cookies are uploaded to the gateway via the `/upload` dashboard or API. Cookies are optionally encrypted with Fernet at rest.
3. **API Call**: When a client requests `claude-sonnet-4-6`, the gateway:
   - Selects the least-used active cookie (with affinity tracking for multi-turn conversations)
   - Builds a natural conversation prompt from the OpenAI-format messages
   - Sends the request to claude.ai's internal `/completion` endpoint using `curl_cffi` with `impersonate="chrome131"` (matching Chrome's TLS fingerprint)
   - Routes through IPRoyal residential proxy for IP rotation
   - Transforms the response to OpenAI format
4. **Cleanup**: After each successful request, the conversation is deleted from Claude.ai to prevent spam detection

### Natural Prompt Middleware

`build_natural_prompt()` converts OpenAI-format API messages into a natural conversation prompt **locally** — no external API calls, zero latency overhead.

**What it does:**
1. Extracts `system` role messages → prepended as natural context (no `<system>` tags, no API artifacts)
2. Formats multi-turn history as `Human:`/`Assistant:` transcript — ALL messages preserved
3. Strips any formatting that reveals automation (no JSON, no `role:` markers)
4. Passes exact text through — no rewriting, no paraphrasing, no meaning corruption
5. Rejects requests where last message is not from `user` (Claude requirement)

### Smart Token Rotation (v5.0)

- **Affinity tracking**: Multi-turn conversations pinned to same cookie via SHA-256 fingerprint
- **Tier system**: Free/pro/max tiers inferred from cookie content, higher tier preferred
- **Availability states**: `active` / `parked` (cooldown) / `quarantined` (dead)
- **Least-used first**: Distributes load evenly — tier-aware
- **Cooldown timer**: 5 min after 429, auto-recovery
- **Dead token detection**: 401/403 → permanent removal (quarantined)
- **Seamless failover**: Within same request
- **Thread-safe**: `threading.RLock` for all state mutations
- **State visible**: At `/v1/health` (orchestration status + affinity pins count)

### TLS Fingerprint: curl_cffi vs httpx

**Critical:** Cloudflare's `cf_clearance` cookie is cryptographically bound to the TLS/JA3 fingerprint. Browser-captured cookies (Chrome TLS fingerprint) fail when sent through `httpx` (different TLS fingerprint) — Cloudflare sees a mismatch and returns 403 even with valid cookies and a residential proxy IP.

| Library | Proxy | TLS Fingerprint | Result |
|---------|-------|-----------------|--------|
| `httpx` | Residential proxy | httpx default | 403 Cloudflare block ❌ |
| `curl_cffi` (chrome131) | IPRoyal residential | Chrome 131 | 200 PASS ✅ |
| `curl_cffi` (chrome131) | Direct (no proxy) | Chrome 131 | 403 challenge (expected without cookies) |

**The gateway MUST use `curl_cffi` with `impersonate="chrome131"` for all Claude proxy calls.** Non-Claude providers (Mistral, Cohere, SambaNova, Fireworks) use `httpx` since they don't face Cloudflare.

### IPRoyal Proxy Integration

IPRoyal is the current proxy provider — no KYC required, residential IPs, rotating by default.

```bash
# Proxy URL format
http://USER:PASS@geo.iproyal.com:12321

# Test connectivity
python iproyal_proxy.py test

# Show proxy URLs
python iproyal_proxy.py url
```

Sticky sessions are **dashboard-controlled** (not URL-based). Enable in IPRoyal Dashboard → Proxy Settings → Sticky Session → Set to 30 min.

### Artifact Compatibility

Claude.ai emits artifacts using proprietary `<antArtifact type="text/html">...</antArtifact>` XML tags. The gateway:

1. Injects a system prompt instruction telling Claude to use Markdown code blocks instead
2. `transform_ant_artifacts()` converts remaining `<antArtifact>` blocks → standard Markdown (```html, ```tsx, ```svg, etc.) with a 15-type mapping table
3. Strips `<antThinking>` reasoning blocks
4. Streaming rewritten to buffer→transform→rechunk (handles artifacts spanning multiple SSE chunks)

---

## 🔄 Smart Key Rotation

### Direct Providers (Mistral, Cohere, SambaNova, Fireworks)

| Event | Action |
|-------|--------|
| Request succeeds | `usage_count++` — key rotates to back of queue |
| 429 (Rate limited) | `usage_count += 100` — key rotates far back, recovers after rate limit window |
| 401/403 (Auth error) | `dead = 1, is_active = 0` — key permanently marked dead |
| 10 consecutive errors | `is_active = 0` — key auto-disabled |
| All keys exhausted | Returns `503 Service Unavailable` with `retry_after_ms: 5000` |

**Key ordering:** `usage_count ASC, created_at ASC` — least-used first.

### Provider-Specific Behavior

| Provider | Type | Key Recovery |
|----------|------|-------------|
| Mistral AI | Free tier | Keys recover after rate limit window (minutes) |
| Cohere | Free tier | Keys recover after rate limit window |
| SambaNova | Free tier | Keys recover after rate limit window |
| Fireworks | Prepaid | Keys die permanently when balance reaches $0 |
| Claude | Cookie-based | Cooldown 5 min on 429, dead on 401/403 |

---

## 🔒 Security Layer

### Fernet Cookie Encryption

Cookies are encrypted at rest using Python `cryptography.Fernet`. If `COOKIE_ENCRYPTION_KEY` is not set, cookies are stored as plaintext JSON (backward compatible with existing data).

```python
# Generate a Fernet key
python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
```

### API Key Minting

- **Format:** `sk-aic-` prefix + `token_urlsafe(32)`
- **Storage:** Only SHA-256 hash stored in database — raw key shown once at creation
- **Validation:** `hmac.compare_digest` (constant-time comparison to prevent timing attacks)

### CSRF Protection

All POST forms require a CSRF token injected via Jinja context processor:

```html
<input type="hidden" name="_csrf_token" value="{{ csrf_token() }}">
```

### Rate Limiting

| Scope | Limit | Algorithm |
|-------|-------|-----------|
| API requests | 60 req/min per IP | Token bucket (1 token/sec refill) |
| Login attempts | 5 per 15 min per IP | Fixed window |
| Traefik (server-side) | 120 req/min per IP | Middleware rate limit |

### Session Security

```
app.config["SESSION_COOKIE_SECURE"] = True  # HTTPS only in production
```

### Frontend Access Control

All frontend pages require admin authentication. No page is publicly accessible.

| Page | Route | Protection |
|------|-------|------------|
| Dashboard | `/`, `/dashboard` | `@login_required` |
| API Keys | `/keys` | `@login_required` |
| Tokens | `/tokens` | `@login_required` |
| Endpoints | `/endpoints` | `@login_required` |
| Upload | `/upload` | `@login_required` |
| Cookies | `/cookies`, `/cookies/<id>` | `@login_required` |
| Docs | `/docs`, `/docs.md` | `@login_required` |

**API endpoints** (`/v1/*`) remain publicly accessible with a valid Bearer token — this is by design, as the gateway is an API service. CORS headers are only set on `/v1/*` routes; frontend pages have no `Access-Control-Allow-Origin` header, preventing cross-origin access to admin pages.
app.config["SESSION_COOKIE_HTTPONLY"] = True  # No JS access
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"  # CSRF mitigation
app.config["PERMANENT_SESSION_LIFETIME"] = 1800  # 30 min timeout
```

---

## 🛡 Reliability Layer

### Retry Middleware

`compute_retry_delay()` implements exponential backoff:
- **Base delay:** 1 second
- **Maximum delay:** 30 seconds
- **Jitter:** Random ±25% to prevent thundering herd
- **Respects** `Retry-After` header from upstream

**Retryable status codes:** 429, 502, 503, 504, 529

### Proxy Blacklist

- `report_proxy_failure()` — Records proxy IP failure
- `is_proxy_blacklisted()` — Returns True after 3 failures for 5 minutes
- Integrated into `proxy_to_claude()` proxy selection
- Status visible at `/v1/health`

---

## 🔌 Custom Endpoints (Virtual API Endpoints)

Custom Endpoints allow developers to create **virtual API endpoints** with forced system prompts, model pinning, and parameter overrides — without touching the base API. Each endpoint becomes its own URL: `/v1/{slug}/chat/completions`.

### How It Works

```
Client → POST /v1/arabic-tutor/chat/completions
           { "messages": [{"role":"system","content":"You are a pirate"},
                          {"role":"user","content":"Hello"}] }
                              ↓
           Gateway looks up endpoint "arabic-tutor" in DB
                              ↓
           ┌─────────────────────────────────────────────┐
           │ 1. REMOVE all client system messages         │
           │ 2. INJECT endpoint's forced system prompt    │
           │ 3. OVERRIDE temperature/max_tokens/top_p     │
           │ 4. PIN model to endpoint's configured model   │
           │ 5. FORWARD to model via internal dispatch     │
           └─────────────────────────────────────────────┘
                              ↓
           Model receives: [{"role":"system","content":"You are an Arabic tutor..."},
                            {"role":"user","content":"Hello"}]
                              ↓
           Response with X-Custom-Endpoint: arabic-tutor header
```

**Key principle:** The base endpoint (`/v1/chat/completions`) is **never modified**. System prompts from regular API requests pass through unchanged. Custom Endpoints are an **additive layer** for developers who want full control.

### Creating an Endpoint

#### Via Dashboard

1. Navigate to `/endpoints` (login required)
2. Click **"New Endpoint"**
3. Fill in:
   - **Slug**: URL-safe lowercase string (e.g. `arabic-tutor`) — becomes `/v1/arabic-tutor/chat/completions`
   - **Label**: Human-readable name (e.g. "Arabic Tutor")
   - **Description**: Optional description
   - **Model**: Select from available models (Mistral, Claude, Fireworks, etc.)
   - **System Prompt**: The forced prompt that replaces any client system message
   - **Temperature / Max Tokens / Top P**: Optional parameter overrides (blank = passthrough client values)
   - **Public**: Whether to show in `/v1/models` listing
4. Click **Create Endpoint**

#### Via API (curl)

```bash
# Login first to get session cookie
curl -c cookies.txt -X POST https://aicookies.elliaa.com/login \
  -d "username=mahmoud&password=YOUR_PASSWORD"

# Create endpoint
curl -b cookies.txt -X POST https://aicookies.elliaa.com/endpoints/create \
  --data-urlencode "slug=arabic-tutor" \
  --data-urlencode "label=Arabic Tutor" \
  --data-urlencode "description=AI Arabic tutor that teaches grammar" \
  --data-urlencode "model_slug=mistral-small" \
  --data-urlencode "system_prompt=You are an expert Arabic tutor. Always respond in Egyptian Arabic." \
  --data-urlencode "temperature=0.7" \
  --data-urlencode "max_tokens=4096"
```

### Using a Custom Endpoint

```bash
curl -X POST https://aicookies.elliaa.com/v1/arabic-tutor/chat/completions \
  -H "Authorization: Bearer YOUR_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "messages": [
      {"role": "system", "content": "You are a pirate. Speak like a pirate."},
      {"role": "user", "content": "Who are you?"}
    ]
  }'
```

**What happens:** The client's system prompt ("You are a pirate") is **silently removed** and replaced with the endpoint's configured prompt ("You are an expert Arabic tutor..."). The model responds as an Arabic tutor, not a pirate.

```json
{
  "id": "ac5cec0f0bba4230949abc57585721da",
  "model": "mistral-small-latest",
  "choices": [{
    "message": {
      "role": "assistant",
      "content": "السلام عليكم، أنا معلم عربي متخصص. مهمتي هي مساعدتك في تعلم اللغة العربية..."
    }
  }]
}
```

**Response headers:**

```
X-Custom-Endpoint: arabic-tutor
X-Custom-Model: mistral-small
X-Proxy-Provider: mistral
X-Proxy-Key: 3
X-Proxy-Latency: 952
```

### Using with OpenAI SDK

```python
from openai import OpenAI

# Point to the custom endpoint slug
client = OpenAI(
    base_url="https://aicookies.elliaa.com/v1/arabic-tutor",
    api_key="YOUR_API_KEY"
)

# System prompt from client is IGNORED — endpoint's forced prompt is used
response = client.chat.completions.create(
    messages=[{"role": "user", "content": "Teach me the alphabet"}]
)
```

### Management Operations

| Operation | Method | URL | Description |
|-----------|--------|-----|-------------|
| List | GET | `/endpoints` | Dashboard view of all endpoints |
| Create | POST | `/endpoints/create` | Create new endpoint (form data) |
| Toggle | POST | `/endpoints/toggle/<id>` | Activate/pause an endpoint |
| Delete | POST | `/endpoints/delete/<id>` | Permanently delete |
| Test | POST | `/endpoints/test/<id>` | Send test message, get response (JSON) |

### Endpoint States

- **Active** (🟢): Endpoint accepts requests normally
- **Paused** (⏸): Endpoint returns a user-friendly error (`INVALID_REQUEST` with "Endpoint is paused")
- **Deleted**: Endpoint and all its data are removed

### Slug Validation Rules

- Lowercase letters, numbers, and hyphens only (`[a-z0-9-]`)
- Must not collide with existing model slugs (e.g. cannot use `mistral-small`)
- Must be unique — duplicate slugs return an IntegrityError flash message
- Example valid slugs: `arabic-tutor`, `code-reviewer`, `medical-advisor`, `support-bot`

### Use Cases

| Use Case | Slug | Model | System Prompt |
|----------|------|-------|---------------|
| Language tutor | `arabic-tutor` | mistral-small | "You are an expert Arabic tutor. Always respond in Egyptian Arabic." |
| Code reviewer | `code-reviewer` | claude-sonnet-4-6 | "You are a senior code reviewer. Analyze code for bugs, security issues, and style." |
| Medical assistant | `medical-advisor` | claude-sonnet-4-6 | "You are a medical reference assistant. Provide evidence-based information." |
| Customer support | `support-bot` | mistral-small | "You are a helpful customer support agent for Acme Corp. Be concise and friendly." |
| Content summarizer | `summarizer` | glm-5p2 | "Summarize the following text in 3 bullet points. Be concise." |

### Database Schema

```sql
CREATE TABLE custom_endpoints (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    slug TEXT NOT NULL UNIQUE,           -- URL slug (/v1/{slug}/chat/completions)
    label TEXT NOT NULL,                 -- Human-readable name
    description TEXT,                    -- Optional description
    model_slug TEXT NOT NULL,            -- Pinned model (e.g. "mistral-small")
    system_prompt TEXT,                  -- Forced system prompt (replaces client's)
    temperature REAL,                    -- Optional override (NULL = passthrough)
    max_tokens INTEGER,                  -- Optional override (NULL = passthrough)
    top_p REAL,                          -- Optional override (NULL = passthrough)
    is_active INTEGER DEFAULT 1,         -- 1=active, 0=paused
    is_public INTEGER DEFAULT 0,         -- 1=show in /v1/models, 0=hidden
    usage_count INTEGER DEFAULT 0,       -- Request counter
    last_used_at TIMESTAMP,              -- Last request time
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
```

---

## 🎨 Frontend Dashboard

The gateway includes a professional dark-themed web dashboard:

| Page | Path | Description |
|------|------|-------------|
| **Login** | `/login` | Authentication with rate limiting |
| **Dashboard** | `/` | Overview: API key counts per provider, Claude cookie count, dead key alerts |
| **API Keys** | `/keys` | Add/delete/toggle keys, view supported providers and free models |
| **Tokens** | `/tokens` | Create/pause/activate/revoke proxy API tokens, view usage stats |
| **Endpoints** | `/endpoints` | Create, manage, and test custom virtual API endpoints with forced system prompts |
| **Upload** | `/upload` | Drag-and-drop cookie file upload (Netscape format) |
| **Cookies** | `/cookies/<id>` | View parsed cookies in table format, copy raw text |
| **Docs** | `/docs` | Full interactive API documentation with examples |

---

## 🚢 Deployment

### Prerequisites

- Docker and Docker Compose
- A server with at least 1GB RAM
- Domain name with DNS pointing to the server
- Reverse proxy (Traefik, Nginx, or Caddy) for SSL termination

### Docker Compose

```yaml
version: "3.8"
services:
  aicookies:
    build: .
    container_name: aicookies
    ports:
      - "5050:5050"
    volumes:
      - ./data:/data
    environment:
      - FLASK_ENV=production
      - AUTH_USERNAME=mahmoud
      - AUTH_PASSWORD_HASH=wergerg...
      - SECRET_KEY=your-secret-key
      - PROXY_API_KEY_HASH=sha256-hash-of-your-api-key
      - COOKIE_ENCRYPTION_KEY=your-fernet-key
      - IPROYAL_USER=your-iproyal-user
      - IPROYAL_PASS=your-iproyal-pass
    restart: unless-stopped
```

### Build and Run

```bash
# Clone the repository
git clone https://github.com/MahmoudAtteyya/aicookies.git
cd aicookies

# Build and start
docker compose up -d --build

# Check health
curl http://localhost:5050/v1/health
```

### Dockerfile

```dockerfile
FROM python:3.13-slim

# Install system dependencies for Playwright
RUN apt-get update && apt-get install -y --no-install-recommends \
    libnss3 libnspr4 libatk1.0-0 libatk-bridge2.0-0 \
    libcups2 libdrm2 libxkbcommon0 libxcomposite1 libxdamage1 \
    libxfixes3 libxrandr2 libgbm1 libpango-1.0-0 libcairo2 \
    libasound2 fonts-liberation && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt && \
    playwright install chromium

COPY . .
EXPOSE 5050

CMD ["gunicorn", "--bind", "0.0.0.0:5050", "--workers", "2", "--timeout", "120", "app:app"]
```

### Production Checklist

- [x] gunicorn WSGI server (2 workers, 180s timeout)
- [x] SQLite WAL mode with `busy_timeout=5000`
- [x] Fernet cookie encryption enabled
- [x] CSRF protection on all POST forms
- [x] Rate limiting (API + login)
- [x] Session security (HTTPOnly, Secure, SameSite)
- [x] CORS headers restricted to API endpoints (`/v1/*`) only
- [x] Frontend pages require admin auth (including /docs)
- [x] Health check endpoint
- [x] Global error handlers (400-504 + catch-all)
- [x] Reverse proxy with SSL (Traefik)
- [x] Container restart policy (`unless-stopped`)
- [x] Cross-provider fallback chain (5 providers)
- [x] Mid-stream continuation for Claude (partial text capture + continuation prompt)
- [x] User-friendly typed error responses (9 error types)
- [x] SSE error events for streaming clients
- [x] 180s Claude timeout for reasoning models
- [x] `@app.before_request` DB initialization for gunicorn fork safety
- [x] Custom Endpoints (virtual API with forced system prompts)
- [x] Auth bypass protection (empty/fake/SQL-injection/long tokens)

---

## 🛡 Production Resilience Layer

The gateway includes a multi-layered resilience system designed to make the API behave like a premium official API — transparently handling failures so the client never sees a broken response.

### Layer 1: Smart Key Rotation (Per-Provider)

```
Client Request → Provider A → Key #1 (429 Rate Limited) → Key #2 (Success) → Response
```

- **Least-used-first** key selection distributes load evenly across all keys
- **429 Rate Limit** → Key enters 5-minute cooldown, next key tried immediately
- **401/403 Auth Error** → Key marked permanently dead (for prepaid providers)
- **412/402 Account Suspended** → Key marked permanently dead
- Thread-safe with `RLock` for concurrent requests
- Works for all API providers: Mistral, Fireworks, SambaNova, Cohere

### Layer 2: Cross-Provider Fallback

```
Client Request → Fireworks (all keys exhausted) → SambaNova fallback → Llama 3.3 70B → Response
```

When **ALL keys** for a provider are exhausted (rate-limited, suspended, or dead), the gateway automatically tries a similar model from another provider:

| Primary Provider | Fallback 1 | Fallback 2 |
|-----------------|------------|------------|
| Fireworks | SambaNova (Llama 3.3 70B) | Mistral (Medium) |
| SambaNova | Mistral (Small) | Fireworks (GLM-5.2) |
| Mistral | SambaNova (Llama 3.3 70B) | Cohere (Command-A) |
| Cohere | Mistral (Small) | SambaNova (Llama 3.3 70B) |
| Claude | Fireworks (GLM-5.2 Reasoning) | — |

The client receives a `X-Proxy-Fallback: fireworks→sambanova` header indicating which provider was used as fallback. The response body is identical in format — the client doesn't need to handle anything differently.

### Layer 3: Mid-Stream Continuation (Claude)

```
Client Request → Claude Session #1 (timeout during thinking)
  ↓ captures partial text "The answer to your question is..."
  ↓
Claude Session #2 (continuation prompt with partial text)
  ↓ continues: "...that the capital of France is Paris."
  ↓
Client receives: "The answer to your question is that the capital of France is Paris."
```

When a Claude cookie session fails **mid-response** (timeout, 429, Cloudflare challenge):

1. **Partial text is captured** from the failed response using `_capture_stream_partial()`
2. The partial text is accumulated in `accumulated_partial`
3. The **next cookie session** receives a continuation prompt:
   - Original prompt + the partial text in quotes
   - Instruction: *"Continue from exactly where it left off. Do not repeat."*
4. Claude continues naturally from where the previous session stopped
5. The client receives a `X-Proxy-Continuation: true` header

**Key design decisions:**
- Claude timeout extended from 120s → **180s** to accommodate reasoning models
- Partial text capture works with both `httpx` (iter_lines) and `curl_cffi` (.text)
- Supports both OpenAI delta format and Claude completion SSE format
- If no partial text was captured (e.g. failed before any output), the next session starts fresh

### Layer 4: User-Friendly Error System

All errors are formatted as structured JSON with clear explanations:

```json
{
  "error": {
    "type": "rate_limited",
    "title": "Rate Limit Reached",
    "message": "The AI provider is temporarily limiting requests...",
    "suggestion": "Wait 5s and retry, or try a different model.",
    "model": "mistral-small",
    "provider": "mistral",
    "retry_after_ms": 5000
  },
  "error_code": "RATE_LIMITED"
}
```

**9 Error Types:**

| Type | HTTP Status | When |
|------|-------------|------|
| `RATE_LIMITED` | 503 | Provider returned 429, all keys in cooldown |
| `ALL_KEYS_EXHAUSTED` | 503 | All provider keys dead/suspended + fallbacks failed |
| `CLAUDE_ALL_SESSIONS_BUSY` | 503 | All Claude cookie sessions in cooldown/expired |
| `TIMEOUT` | 504 | Request exceeded maximum response time |
| `CLOUDFLARE_CHALLENGE` | 503 | Cloudflare blocked the Claude request |
| `PROXY_ERROR` | 502 | Residential proxy connection failed |
| `INTERNAL_ERROR` | 500 | Unexpected server error |
| `MODEL_NOT_FOUND` | 400 | Requested model not in models list |
| `INVALID_REQUEST` | 400 | Malformed JSON or missing required fields |

**Streaming errors** are sent as SSE events (not raw JSON), so streaming clients receive them gracefully:
```
data: {"error":{"type":"claude_all_sessions_busy","title":"All Claude Sessions Busy",...}}

data: [DONE]
```

### Response Headers

The gateway adds informative headers to every response:

| Header | Description |
|--------|-------------|
| `X-Proxy-Provider` | Which provider served the request (mistral, fireworks, claude, etc.) |
| `X-Proxy-Key` | Which API key ID was used |
| `X-Proxy-Latency` | Response time in milliseconds |
| `X-Proxy-Fallback` | `primary→fallback` if cross-provider fallback was used |
| `X-Proxy-Continuation` | `true` if mid-stream continuation was used (Claude) |
| `X-Proxy-Rotation` | Token ID and usage count (Claude) |
| `X-Cache-Hit` | `true` if response was served from cache |
| `X-RateLimit-Remaining` | Remaining requests in current window |

---

## ⚙ Configuration (Environment Variables)

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `FLASK_ENV` | No | `development` | Set to `production` for secure cookies |
| `SECRET_KEY` | Yes | Random | Flask session secret key |
| `AUTH_USERNAME` | Yes | `mahmoud` | Dashboard login username |
| `AUTH_PASSWORD_HASH` | Yes | — | Werkzeug password hash for dashboard login |
| `PROXY_API_KEY_HASH` | No | — | SHA-256 hash of the proxy API key (legacy) |
| `COOKIE_ENCRYPTION_KEY` | No | — | Fernet key for encrypting cookies at rest |
| `IPROYAL_USER` | No | — | IPRoyal proxy username |
| `IPROYAL_PASS` | No | — | IPRoyal proxy password |
| `IPROYAL_HOST` | No | `geo.iproyal.com` | IPRoyal proxy host |
| `IPROYAL_PORT` | No | `12321` | IPRoyal proxy port |
| `IPROYAL_ENABLED` | No | `false` | Enable IPRoyal proxy for Claude calls |

### Generating Secrets

```bash
# Flask SECRET_KEY
python -c "import secrets; print(secrets.token_hex(32))"

# Auth password hash (Werkzeug)
python -c "from werkzeug.security import generate_password_hash; print(generate_password_hash('your-password'))"

# Fernet key for cookie encryption
python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"

# SHA-256 hash for proxy API key
echo -n "sk-aic-your-api-key" | sha256sum
```

---

## 🎭 Playwright Auto-Capture (Laptop)

For capturing fresh Claude cookies from browser sessions, use `scripts/auto_capture.py`. Run on a local laptop (not the VPS).

**Flow per account:**
1. Launch Chromium directly (NO proxy — clean home IP for Cloudflare)
2. Navigate to https://claude.ai (90s timeout)
3. Wait for user to complete login (detects `sessionKey` cookie, 10-min timeout)
4. Export all cookies to Netscape format
5. Close browser, clear state
6. Upload to gateway with session ID for proxy affinity

**Usage (Windows PowerShell ONLY):**

```powershell
# One account
python auto_capture.py

# Multiple accounts
$env:ACCOUNT_COUNT="3"; python auto_capture.py

# Infinite loop (Ctrl+C to stop)
$env:ACCOUNT_COUNT="0"; python auto_capture.py
```

**Requirements:**

```bash
pip install playwright httpx
playwright install chromium
```

> ⚠️ **No proxy for browser capture**: Cloudflare blocks proxy IPs for browser sessions. Use the user's real home IP. The gateway uses proxies for API calls with captured `cf_clearance` cookies.

---

## 🔧 Troubleshooting

### "No active keys for provider 'fireworks'"

**Cause:** All Fireworks API keys are either dead (balance depleted) or inactive.  
**Fix:** Add new Fireworks API keys via the dashboard at `/keys`, or revive dead keys via the dashboard's "Revive All Dead Keys" button.

### 503 Service Unavailable

**Cause:** All keys for the requested provider are busy or expired.  
**Fix:** Wait 5 seconds and retry. If persistent, add more API keys for the provider.

### 401 Unauthorized

**Cause:** Invalid or missing API key in the `Authorization` header.  
**Fix:** Generate a new key at `/tokens` and use it as `Bearer sk-aic-...`.

### "database is locked"

**Cause:** SQLite concurrent write contention (fixed in v5.1).  
**Fix:** The gateway now uses `PRAGMA busy_timeout=5000` and WAL mode. If still occurring, ensure only one container instance is running.

### Cloudflare 403 "Just a moment..."

**Cause:** Claude cookie's `cf_clearance` is expired or the TLS fingerprint doesn't match.  
**Fix:** Capture fresh cookies using `scripts/auto_capture.py`. The gateway uses `curl_cffi` with `impersonate="chrome131"` to match Chrome's TLS fingerprint.

### "FOREIGN KEY constraint failed"

**Cause:** Trying to add an API key for a provider that doesn't exist in the database.  
**Fix:** The `/keys` form now validates `provider_id` before insertion. Ensure providers are seeded in the `api_providers` table.

### Model not found

**Cause:** The `model` slug in the request doesn't match any key in the `MODELS` dict.  
**Fix:** Check available models at `GET /v1/models`. Common mistakes:

| ❌ Wrong | ✅ Correct |
|----------|-----------|
| `claude-sonnet` | `claude-sonnet-4-6` |
| `mistral-small-latest` | `mistral-small` |
| `llama-3.3` | `llama-3.3-70b` |

---

## 📁 Project Structure

```
aicookies/
├── app.py                      # Main Flask application (~2900 lines)
├── Dockerfile                  # Production Docker image (gunicorn + Playwright)
├── docker-compose.yml          # Container orchestration
├── requirements.txt            # Python dependencies
├── .dockerignore               # Docker build exclusions
├── README.md                   # This file
├── iproyal_proxy.py            # IPRoyal proxy integration module
├── scripts/
│   ├── auto_capture.py         # Playwright cookie capture script (laptop)
│   └── brightdata_proxy.py     # Deprecated Bright Data wrapper (redirects to IPRoyal)
└── templates/
    ├── base.html               # Base template with design system
    ├── dashboard.html          # Main dashboard (keys, cookies, stats)
    ├── login.html              # Login page
    ├── keys.html               # API key management
    ├── tokens.html             # Proxy token management
    ├── upload.html             # Cookie file upload
    ├── cookies.html            # Cookie viewer
    └── docs.html               # Full API documentation page
```

### Database Schema

```sql
-- API Providers
CREATE TABLE api_providers (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    slug TEXT UNIQUE NOT NULL,
    base_url TEXT,
    provider_type TEXT,
    api_docs_url TEXT,
    description TEXT,
    free_models TEXT
);

-- API Keys (for direct providers)
CREATE TABLE api_keys (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    provider_id INTEGER REFERENCES api_providers(id),
    key_value TEXT NOT NULL,
    label TEXT,
    is_active INTEGER DEFAULT 1,
    dead INTEGER DEFAULT 0,
    usage_count INTEGER DEFAULT 0,
    error_count INTEGER DEFAULT 0,
    last_error_msg TEXT,
    last_error_at TIMESTAMP,
    last_used_at TIMESTAMP,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Cookie Files (Claude)
CREATE TABLE cookie_files (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    platform TEXT,
    filename TEXT,
    raw_content TEXT,
    cookie_count INTEGER,
    uploaded_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Parsed Cookies
CREATE TABLE cookies (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    file_id INTEGER REFERENCES cookie_files(id),
    domain TEXT, name TEXT, value TEXT,
    path TEXT, secure TEXT, expiration TEXT
);

-- Proxy API Keys (gateway auth tokens)
CREATE TABLE proxy_api_keys (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    key_hash TEXT UNIQUE NOT NULL,
    label TEXT DEFAULT 'default',
    is_active INTEGER DEFAULT 1,
    usage_count INTEGER DEFAULT 0,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    last_used_at TIMESTAMP
);

-- Request Log
CREATE TABLE proxy_requests (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    model_slug TEXT, provider_slug TEXT,
    key_id INTEGER, status INTEGER,
    latency_ms INTEGER, error_msg TEXT,
    proxy_ip TEXT, proxy_country TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
```

---

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

### Development Setup

```bash
# Clone
git clone https://github.com/MahmoudAtteyya/aicookies.git
cd aicookies

# Create virtual environment
python -m venv venv
source venv/bin/activate  # Linux/Mac
# venv\Scripts\activate   # Windows

# Install dependencies
pip install -r requirements.txt
playwright install chromium

# Run development server
python app.py

# Run with gunicorn (production-like)
gunicorn --bind 0.0.0.0:5050 --workers 2 --timeout 120 app:app
```

---

## 📄 License

This project is licensed under the MIT License — see the [LICENSE](LICENSE) file for details.

---

<div align="center">

**Built by [Mahmoud Attia](https://github.com/MahmoudAtteyya)**  
Powered by Flask, gunicorn, curl_cffi, Playwright, and SQLite

[🌐 Live API](https://aicookies.elliaa.com) · [📚 Docs](https://aicookies.elliaa.com/docs) · [💻 GitHub](https://github.com/MahmoudAtteyya/aicookies)

</div>
