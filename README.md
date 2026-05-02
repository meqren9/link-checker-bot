# SafeLiinkBot

Telegram bot that checks links before opening them.

## Features

- Detects links in Telegram text messages.
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
ADMIN_USER_IDS=/myid

```

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

## Run

```bash
python main.py
```

## Run API Locally

The FastAPI backend is separate from the Telegram polling bot, so the bot can
continue running with `python main.py`.

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

## Notes

- The local scan is a lightweight heuristic check and does not guarantee safety.
- A clean result does not guarantee that a link is safe.
- VirusTotal is not enabled yet.
