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
- Offers an optional Mini App VirusTotal scan only after the local scan.
- Lets users report suspicious links from Telegram or the Mini App.
- Marks a domain or URL hash as community suspicious after 5 reports.
- Shows existing community report counts in scan results.
- Provides admin commands to list reports and clear a domain report.
- Warns in group chats when high-risk links or community-reported links are
  detected.
- Can optionally delete suspicious group messages when enabled and the bot is a
  group admin.
- Provides `/privacy` with the report data handling policy.

## Environment Variables

Required:

```env
BOT_TOKEN=your_telegram_bot_token
```

Optional:

```env
WEBAPP_URL=https://your-app.up.railway.app
VT_API_KEY=your_virustotal_api_key
DELETE_SUSPICIOUS=false
ADMIN_USER_IDS=123456789
COMMUNITY_REPORTS_FILE=community_reports.json
```

`WEBAPP_URL` is the public HTTPS URL for the Telegram Mini App. When set, `/start`
shows a button that opens the Mini App. Leave it empty to keep `/start` as a
plain text reply.

`VT_API_KEY` enables the Mini App advanced VirusTotal scan. The key is read only
by the FastAPI backend and is never sent to the frontend. The Mini App runs the
local scan first, then calls VirusTotal only when the user clicks the advanced
scan button. Results are cached in memory for 24 hours to reduce repeated calls
and stay friendly to free API limits.

`DELETE_SUSPICIOUS` defaults to `false`. When set to `true`, group safety still
acts only on high-confidence cases: local scan score `60` or higher, or
community reports at the configured threshold. The bot deletes the message only
if it is an admin in that group; otherwise it sends the Arabic warning message.

`ADMIN_USER_IDS` is a comma-separated list of numeric Telegram `user.id` values.
Users in this list bypass the scan rate limit. The example above configures
Telegram `user.id` `/myid
` as an admin. Use `/myid` in the bot to find the
numeric ID for an account. Usernames such as `@example` are not matched for
admin access and are ignored.

`COMMUNITY_REPORTS_FILE` controls where community report counts are stored. The
file stores report keys and counts only. A report key is the registered domain
when available, such as `example.com`, or a SHA-256 URL hash fallback. Full URLs,
paths, and query strings are not stored in the report file. Reporter identifiers
are hashed per report key and used only to avoid counting duplicate reports from
the same user.

Admins configured in `ADMIN_USER_IDS` can use `/reports` to view the highest
reported domains or URL hashes. Use `/clearreport example.com` to remove the
stored report count for a domain. The clear command accepts a domain, not a full
sensitive URL.

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

Advanced VirusTotal scan:

```bash
curl -X POST http://127.0.0.1:8000/api/scan/vt \
  -H "Content-Type: application/json" \
  -d '{"url":"https://example.com","initData":"telegram-init-data"}'
```

New Mini App calls should use the main scan endpoint with `advanced=true`:

```bash
curl -X POST http://127.0.0.1:8000/api/scan \
  -H "Content-Type: application/json" \
  -d '{"url":"https://example.com","initData":"telegram-init-data","advanced":true}'
```

Advanced scans require `VT_API_KEY` on the backend. The API returns an Arabic
summary only and does not expose the VirusTotal key or raw secret configuration.

Report a suspicious URL:

```bash
curl -X POST http://127.0.0.1:8000/api/report \
  -H "Content-Type: application/json" \
  -d '{"url":"https://example.com/private/path","initData":"telegram-init-data"}'
```

The response includes the safe URL label, report count, threshold, and whether
the item is now community suspicious.

Mini App frontend:

```text
http://127.0.0.1:8000/
```

The frontend only sends the entered URL and Telegram Mini App `initData` to
`/api/scan`. Secrets such as `BOT_TOKEN` and future API keys stay server-side.

## Notes

- The local scan is a lightweight heuristic check and does not guarantee safety.
- A clean result does not guarantee that a link is safe.
- VirusTotal free API limits can be reached during heavy use; the Mini App shows
  a friendly Arabic message when that happens.
- Group protection warns by default. Message deletion is opt-in with
  `DELETE_SUSPICIOUS=true` and requires the bot to be a group admin.
