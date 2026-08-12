from flask import Flask, request, jsonify
from flask_cors import CORS
import json
from scraper import (
    scrape_profile,
    analyze_domain,
    flag_suspicious_urls,
    check_username_cross_platform,
    compute_risk_score,
)

app = Flask(__name__)
CORS(app)

# Store creds in memory (set via /config)
_config = {"ig_user": "", "ig_pass": ""}


@app.route("/config", methods=["POST"])
def set_config():
    data = request.json
    _config["ig_user"] = data.get("ig_user", "")
    _config["ig_pass"] = data.get("ig_pass", "")
    return jsonify({"status": "ok"})


@app.route("/scan", methods=["POST"])
def scan():
    data = request.json
    target = data.get("target", "").strip()

    if not target:
        return jsonify({"error": "No target provided"}), 400
    if not _config["ig_user"]:
        return jsonify({"error": "Instagram credentials not set — POST /config first"}), 400

    # 1. Scrape profile
    profile = scrape_profile(target, _config["ig_user"], _config["ig_pass"])
    if "error" in profile:
        return jsonify(profile), 400

    # 2. Flag suspicious URLs
    flagged = flag_suspicious_urls(profile.get("all_urls", []))

    # 3. Analyze domains (limit to 5 to keep response fast)
    domain_results = []
    for url in profile.get("all_urls", [])[:5]:
        domain_results.append(analyze_domain(url))

    # 4. Cross-platform check
    platforms = check_username_cross_platform(profile["username"])

    # 5. Risk score
    risk = compute_risk_score(profile, flagged, domain_results)

    return jsonify({
        "profile": profile,
        "flagged_urls": flagged,
        "domain_analysis": domain_results,
        "cross_platform": platforms,
        "risk": risk,
    })


@app.route("/health")
def health():
    return jsonify({"status": "ok", "logged_in": bool(_config["ig_user"])})


if __name__ == "__main__":
    app.run(port=5050, debug=True)
