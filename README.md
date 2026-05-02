# SafeLiinkBot

Telegram bot that checks links before opening them.

## Features

- Detects links in Telegram text messages.
- Checks up to 3 links per message.
- Runs a local heuristic scan only.
- Limits each user to 5 scans per minute.
- Rejects overly long messages and URLs.
- Does not show full URLs in replies.

## Environment Variables

Required:

```env
BOT_TOKEN=your_telegram_bot_token
```

## Setup

```bash
pip install -r requirements.txt
cp .env.example .env
```

Then edit `.env` with your Telegram bot token.

## Run

```bash
python main.py
```

## Notes

- The local scan is a lightweight heuristic check and does not guarantee safety.
- A clean result does not guarantee that a link is safe.
- VirusTotal is not enabled yet.
