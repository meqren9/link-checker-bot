# SafeLiinkBot

Telegram bot that checks links before opening them.

## Features

- Detects links in Telegram text messages.
- Serves a simple Telegram Mini App for scanning one link from the browser UI.
- Checks up to 3 links per message.
- Replies to `/myid` with the sender's Telegram `user.id` and username.
- Runs a local heuristic scan only.
- Limits normal users to 3 scans per minute.
- Allows configured admin users to scan without rate limits.
- Rejects overly long messages and URLs.
- Does not show full URLs in replies.

## Environment Variables

Required:

```env
BOT_TOKEN=your_telegram_bot_token
```

Optional:

```env
WEBAPP_URL=https://your-app.up.railway.app
ADMIN_USER_IDS=123456789
```

`WEBAPP_URL` is the public HTTPS URL for the Telegram Mini App. When set, `/start`
shows a button that opens the Mini App. Leave it empty to keep `/start` as a
plain text reply.

`ADMIN_USER_IDS` is a comma-separated list of numeric Telegram `user.id` values.
Users in this list bypass the scan rate limit. The example above configures
Telegram `user.id` `/myid
` as an admin. Use `/myid` in the bot to find the
numeric ID for an account. Usernames such as `@example` are not matched for
admin access and are ignored.

## Setup

```bash
pip install -r requirements.txt
cp .env.example .env
```

Then edit `.env` with your Telegram bot token and any admin Telegram user IDs.
For the Mini App button, also set `WEBAPP_URL` to your deployed HTTPS app URL.

## Run

```bash
python main.py
```

## Run API Locally

`python main.py` starts the FastAPI backend and keeps the Telegram polling bot
running. The same FastAPI app serves the Mini App frontend at `/`.

Install dependencies, then start the API with:

```bash
uvicorn api:app --reload
```

Health check:

```bash
curl http://127.0.0.1:8000/health
```

Scan a URL:

```bash
curl -X POST http://127.0.0.1:8000/api/scan \
  -H "Content-Type: application/json" \
  -d '{"url":"https://example.com","initData":"telegram-init-data"}'
```

The API requires `initData` in the request for Mini App compatibility, but this
phase only performs basic input validation and local URL scanning.

Mini App frontend:

```text
http://127.0.0.1:8000/
```

The frontend only sends the entered URL and Telegram Mini App `initData` to
`/api/scan`. Secrets such as `BOT_TOKEN` and future API keys stay server-side.

## Notes

- The local scan is a lightweight heuristic check and does not guarantee safety.
- A clean result does not guarantee that a link is safe.
- VirusTotal is not enabled yet.
