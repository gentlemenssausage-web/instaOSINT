# InstaOSINT

## Setup

```bash
pip install instagrapi requests python-whois dnspython flask flask-cors
```

## Run

```bash
python app.py
```

Then open `instaosint.html` in your browser.

## Usage

1. Enter your burner Instagram username + password → click **Connect**
2. Paste any Instagram URL or @username → click **SCAN**
3. Wait ~15-30 seconds while it:
   - Logs into Instagram via Instagrapi
   - Pulls full profile + recent posts
   - Extracts all URLs from bio and captions
   - Checks cross-platform username presence
   - Analyzes linked domains (WHOIS, DNS, IP)
   - Flags suspicious URLs
   - Computes risk score

## API Endpoints

- `POST /config` — set IG credentials `{ig_user, ig_pass}`
- `POST /scan`   — scan target `{target: "@username or URL"}`
- `GET  /health` — check status

## Add API Keys (optional, for better results)

In scraper.py, add:
- `VIRUSTOTAL_KEY` — free at virustotal.com
- `HUNTER_KEY`    — free tier at hunter.io (email lookup on linked domains)
- `URLSCAN_KEY`   — free at urlscan.io

## Notes

- First scan is slow (~20-30s) because Instagram login + data fetch
- Subsequent scans are faster (session cached)
- Use rotating proxies if you get rate limited
- Keep delay_range in scraper.py at [2,5] minimum to avoid bans
