import re
import time
import json
import socket
import requests
import whois
import dns.resolver
from urllib.parse import urlparse
from instagrapi import Client
from instagrapi.exceptions import LoginRequired, UserNotFound, PrivateError

# ─── Instagram Auth ───────────────────────────────────────────────
_cl = None

def get_client(username: str, password: str) -> Client:
    global _cl
    if _cl:
        return _cl
    cl = Client()
    cl.delay_range = [2, 5]
    cl.login(username, password)
    _cl = cl
    return cl


# ─── Profile Scrape ───────────────────────────────────────────────
def scrape_profile(target: str, ig_user: str, ig_pass: str) -> dict:
    cl = get_client(ig_user, ig_pass)

    # strip URL to username
    target = target.strip().rstrip("/")
    if "/" in target:
        target = target.split("/")[-1]
    target = target.lstrip("@")

    try:
        info = cl.user_info_by_username(target)
    except UserNotFound:
        return {"error": f"User @{target} not found"}
    except PrivateError:
        return {"error": f"Account @{target} is private"}
    except LoginRequired:
        return {"error": "Instagram login failed — check credentials"}

    uid = info.pk

    # grab recent posts (up to 12)
    try:
        medias = cl.user_medias(uid, amount=12)
    except Exception:
        medias = []

    posts = []
    all_urls = []

    for m in medias:
        caption = m.caption_text or ""
        urls = extract_urls(caption)
        all_urls.extend(urls)
        posts.append({
            "id": str(m.pk),
            "caption": caption[:300],
            "urls_found": urls,
            "likes": m.like_count,
            "comments": m.comment_count,
            "timestamp": str(m.taken_at),
        })

    # bio URLs
    bio = info.biography or ""
    bio_urls = extract_urls(bio)
    if info.external_url:
        bio_urls.append(info.external_url)
    all_urls.extend(bio_urls)

    # deduplicate
    all_urls = list(set(all_urls))

    profile = {
        "username": info.username,
        "full_name": info.full_name,
        "bio": bio,
        "bio_urls": bio_urls,
        "followers": info.follower_count,
        "following": info.following_count,
        "post_count": info.media_count,
        "is_private": info.is_private,
        "is_verified": info.is_verified,
        "is_business": info.is_business,
        "business_category": getattr(info, "business_category_name", None),
        "profile_pic_url": str(info.profile_pic_url),
        "pk": str(uid),
        "posts": posts,
        "all_urls": all_urls,
    }
    return profile


# ─── URL Extraction ───────────────────────────────────────────────
URL_RE = re.compile(
    r"https?://[^\s\"'<>)]+|"
    r"(?<!\w)(?:[a-z0-9\-]+\.)+(?:com|net|org|io|co|ru|xyz|tk|ml|ga|cf|gq|pw|top|link|click|download|live|gg|app|dev|me)[^\s\"'<>)]*",
    re.IGNORECASE,
)

def extract_urls(text: str) -> list:
    found = URL_RE.findall(text)
    cleaned = []
    for u in found:
        if not u.startswith("http"):
            u = "http://" + u
        cleaned.append(u)
    return list(set(cleaned))


# ─── Domain Analysis ─────────────────────────────────────────────
def analyze_domain(url: str) -> dict:
    parsed = urlparse(url)
    domain = parsed.netloc or parsed.path
    domain = domain.split(":")[0].lstrip("www.")

    result = {"url": url, "domain": domain}

    # WHOIS
    try:
        w = whois.whois(domain)
        result["whois"] = {
            "registrar": w.registrar,
            "creation_date": str(w.creation_date),
            "expiration_date": str(w.expiration_date),
            "country": w.country,
            "name_servers": w.name_servers,
        }
    except Exception as e:
        result["whois"] = {"error": str(e)}

    # DNS
    try:
        answers = dns.resolver.resolve(domain, "A")
        ips = [r.address for r in answers]
        result["dns"] = {"a_records": ips}
        if ips:
            try:
                result["dns"]["reverse"] = socket.gethostbyaddr(ips[0])[0]
            except Exception:
                pass
    except Exception as e:
        result["dns"] = {"error": str(e)}

    # VirusTotal (free, no key needed for basic URL check)
    result["virustotal_url"] = f"https://www.virustotal.com/gui/url/{requests.utils.quote(url, safe='')}/detection"

    # URLScan.io submit
    try:
        r = requests.post(
            "https://urlscan.io/api/v1/scan/",
            headers={"Content-Type": "application/json"},
            json={"url": url, "visibility": "unlisted"},
            timeout=8,
        )
        if r.status_code == 200:
            result["urlscan"] = r.json().get("result")
        else:
            result["urlscan"] = None
    except Exception:
        result["urlscan"] = None

    return result


# ─── Malware Link Check ───────────────────────────────────────────
PHISH_PATTERNS = re.compile(
    r"(free.?gift|click.?here|verify.?account|confirm.?password|"
    r"bit\.ly|tinyurl|t\.co|ow\.ly|is\.gd|buff\.ly|cutt\.ly|"
    r"\.tk|\.ml|\.ga|\.cf|\.gq|download|install|crack|keygen|"
    r"earn.?money|work.?from.?home|crypto|nft.?drop|airdrop)",
    re.IGNORECASE,
)

def flag_suspicious_urls(urls: list) -> list:
    flagged = []
    for url in urls:
        flags = []
        if PHISH_PATTERNS.search(url):
            flags.append("suspicious_pattern")
        parsed = urlparse(url)
        domain = parsed.netloc.lstrip("www.")
        tld = domain.split(".")[-1] if "." in domain else ""
        if tld in ["tk", "ml", "ga", "cf", "gq", "pw", "xyz", "top"]:
            flags.append("suspicious_tld")
        if len(domain) > 40:
            flags.append("long_domain")
        if flags:
            flagged.append({"url": url, "flags": flags})
    return flagged


# ─── Cross-Platform Username Check ───────────────────────────────
PLATFORMS = {
    "Twitter/X":   "https://twitter.com/{}",
    "TikTok":      "https://www.tiktok.com/@{}",
    "YouTube":     "https://www.youtube.com/@{}",
    "GitHub":      "https://github.com/{}",
    "Reddit":      "https://www.reddit.com/user/{}",
    "Pinterest":   "https://www.pinterest.com/{}",
    "Twitch":      "https://www.twitch.tv/{}",
    "Snapchat":    "https://www.snapchat.com/add/{}",
    "Telegram":    "https://t.me/{}",
}

def check_username_cross_platform(username: str) -> dict:
    headers = {"User-Agent": "Mozilla/5.0 (compatible; OSINT-bot/1.0)"}
    found = {}
    for platform, url_tpl in PLATFORMS.items():
        url = url_tpl.format(username)
        try:
            r = requests.get(url, headers=headers, timeout=6, allow_redirects=True)
            exists = r.status_code == 200 and "not found" not in r.text.lower()[:500]
            found[platform] = {"url": url, "exists": exists, "status": r.status_code}
        except Exception as e:
            found[platform] = {"url": url, "exists": False, "error": str(e)}
        time.sleep(0.3)
    return found


# ─── Risk Score ──────────────────────────────────────────────────
def compute_risk_score(profile: dict, flagged_urls: list, domain_results: list) -> dict:
    score = 0
    reasons = []

    if profile.get("followers", 0) < 50 and profile.get("post_count", 0) > 20:
        score += 20
        reasons.append("High posts, very low followers (bot pattern)")

    ratio = profile.get("following", 0) / max(profile.get("followers", 1), 1)
    if ratio > 5:
        score += 15
        reasons.append(f"Following/follower ratio extremely high ({ratio:.1f}x)")

    if flagged_urls:
        score += len(flagged_urls) * 20
        reasons.append(f"{len(flagged_urls)} suspicious URL(s) found")

    if not profile.get("is_verified") and profile.get("followers", 0) > 10000:
        score += 5
        reasons.append("Large unverified account")

    bio = profile.get("bio", "")
    if any(w in bio.lower() for w in ["dm for", "link in bio", "free", "earn", "crypto", "nft"]):
        score += 10
        reasons.append("Suspicious bio keywords")

    score = min(score, 100)
    level = "LOW" if score < 30 else "MEDIUM" if score < 60 else "HIGH"

    return {"score": score, "level": level, "reasons": reasons}
