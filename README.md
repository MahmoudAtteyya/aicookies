# AI Cookies Manager

Upload, store, and retrieve browser cookies for AI platforms (Claude, ChatGPT, Gemini).

## Features

- 📤 Upload Netscape-format cookie files
- 🔍 Auto-detect platform (Claude, ChatGPT, Gemini)
- 🗄️ SQLite storage with full cookie parsing
- 🔐 Basic authentication (configurable via env)
- 📋 API endpoints for programmatic access
- 🎨 Dark-themed responsive UI

## Usage

### Web Interface

1. Login at `/login`
2. Upload cookie `.txt` files at `/upload`
3. View and manage stored cookies at `/`

### API Endpoints

```bash
# Login
curl -X POST https://aicookies.elliaa.com/api/login \
  -H "Content-Type: application/json" \
  -d '{"username":"mahmoud","password":"Mmm12011305"}' -c cookies.txt

# List all cookie sets
curl https://aicookies.elliaa.com/api/cookies -b cookies.txt

# Get raw cookie text (for curl)
curl https://aicookies.elliaa.com/api/cookies/raw/1 -b cookies.txt

# Get latest Claude cookies
curl https://aicookies.elliaa.com/api/cookies/latest?platform=claude -b cookies.txt
```

## Deploy

```bash
docker compose up -d
```

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `AUTH_USERNAME` | `mahmoud` | Login username |
| `AUTH_PASSWORD` | `Mmm12011305` | Login password |
| `SECRET_KEY` | random | Flask session secret |
| `DB_PATH` | `/data/cookies.db` | SQLite database path |

## Cookie Format

Netscape HTTP Cookie format — standard export from browser extensions like "cookies.txt":

```
.claude.ai	TRUE	/	TRUE	1784904407	sessionKey	sk-ant-sid02-...
```
