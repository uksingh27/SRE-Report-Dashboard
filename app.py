from flask import Flask, request, jsonify, send_file, render_template
from werkzeug.utils import secure_filename
from flask_cors import CORS
import os
import io
import uuid
import pandas as pd


app = Flask(__name__)
app.secret_key = "change-me"
CORS(app, resources={r"/api/*": {"origins": "*"}})


UPLOAD_FOLDER = os.path.join(os.getcwd(), "uploads")
os.makedirs(UPLOAD_FOLDER, exist_ok=True)


def extract_domain_from_email(email: str) -> str:
    if not isinstance(email, str):
        return ""
    email = email.strip()
    if "@" not in email:
        return ""
    return email.split("@", 1)[1].lower()

def map_email_provider(domain: str) -> str:
    if not domain:
        return "unknown"
    common = {
        "gmail.com": "Gmail",
        "googlemail.com": "Gmail",
        "outlook.com": "Outlook",
        "hotmail.com": "Outlook",
        "live.com": "Outlook",
        "msn.com": "Outlook",
        "yahoo.com": "Yahoo",
        "yahoo.co.in": "Yahoo",
        "icloud.com": "iCloud",
        "aol.com": "AOL",
        "proton.me": "Proton",
        "protonmail.com": "Proton",
        "zoho.com": "Zoho",
    }
    if domain in common:
        return common[domain]
    # fallback: take registrable part (last two labels)
    parts = domain.split('.')
    if len(parts) >= 2:
        return parts[-2] + "." + parts[-1]
    return domain

def load_suspicious_domains() -> set:
    suspicious_path = os.path.join(os.getcwd(), "SuspiciousDomains.xlsx")
    if not os.path.exists(suspicious_path):
        return set()
    try:
        susp_df = pd.read_excel(suspicious_path, engine="openpyxl")
    except Exception:
        return set()
    susp_col_candidates = [
        "domain", "domains", "suspicious_domain", "suspicious_domains", "DOMAIN", "Domains"
    ]
    suspicious_col = None
    for col in susp_df.columns:
        if str(col).strip() in susp_col_candidates:
            suspicious_col = col
            break
    if suspicious_col is None and len(susp_df.columns) > 0:
        suspicious_col = susp_df.columns[0]
    if suspicious_col is None:
        return set()
    return set(
        d.strip().lower() for d in susp_df[suspicious_col].astype(str).fillna("") if d and d.strip()
    )

def analyze_dataframe(user_df: pd.DataFrame, suspicious_domains: set) -> dict:
    if "ACTOR_USER_EMAIL" not in user_df.columns:
        raise ValueError("Column 'ACTOR_USER_EMAIL' not found in sheet 'UserManager'.")

    result_df = user_df.copy()
    result_df["email_domain"] = result_df["ACTOR_USER_EMAIL"].apply(extract_domain_from_email)
    result_df["provider"] = result_df["email_domain"].apply(map_email_provider)
    # Flag logic: gmail.com -> special flag; domains in suspicious list -> suspicious
    def compute_flag(domain: str) -> str:
        if domain == "gmail.com":
            return "suspicious - further checks required"
        if domain in suspicious_domains:
            return "suspicious"
        return "safe"

    result_df["flag"] = result_df["email_domain"].apply(compute_flag)
    result_df["suspicious"] = result_df["flag"].apply(lambda f: f != "safe")
    result_df["severity"] = result_df["flag"].apply(lambda f: "medium" if f.startswith("suspicious but") else ("high" if f == "suspicious" else "none"))
    result_rows = result_df[["ACTOR_USER_EMAIL", "email_domain", "provider", "flag", "suspicious", "severity"]]

    total = len(result_rows)
    suspicious_count = int(result_rows["suspicious"].sum())
    safe_count = total - suspicious_count

    # Top suspicious domains
    top_suspicious = (
        result_rows[result_rows["suspicious"]]
        .groupby("email_domain")
        .size()
        .sort_values(ascending=False)
        .head(10)
    )
    top_suspicious_list = [
        {"domain": dom, "count": int(cnt)} for dom, cnt in top_suspicious.items()
    ]

    # Provider breakdown
    provider_breakdown_series = result_rows.groupby("provider").size().sort_values(ascending=False)
    provider_breakdown = [
        {"provider": prov, "count": int(cnt)} for prov, cnt in provider_breakdown_series.items()
    ]

    return {
        "summary": {
            "total": total,
            "suspicious": suspicious_count,
            "safe": safe_count,
        },
        "topSuspiciousDomains": top_suspicious_list,
        "providerBreakdown": provider_breakdown,
        "rows": result_rows.to_dict(orient="records"),
    }


@app.route("/api/health", methods=["GET"])
def health():
    return jsonify({"status": "ok"})

@app.route("/", methods=["GET"]) 
def dashboard():
    return render_template("dashboard.html")

@app.route("/api/analyze", methods=["POST"])
def api_analyze():
    app.logger.info("/api/analyze: received request")
    if "file" not in request.files:
        return jsonify({"error": "No file provided under form field 'file'"}), 400
    file = request.files["file"]
    if file.filename == "":
        return jsonify({"error": "Empty filename"}), 400

    filename = secure_filename(file.filename)
    user_file_path = os.path.join(UPLOAD_FOLDER, f"{uuid.uuid4()}_{filename}")
    file.save(user_file_path)

    try:
        app.logger.info("/api/analyze: saving upload and reading Excel")
        user_df = pd.read_excel(user_file_path, sheet_name="UserManager", engine="openpyxl")
    except Exception as exc:
        app.logger.exception("/api/analyze: failed to read Excel")
        return jsonify({"error": f"Failed to read Excel: {exc}"}), 400
    finally:
        try:
            os.remove(user_file_path)
        except Exception:
            pass

    app.logger.info("/api/analyze: computing analysis")
    suspicious_domains = load_suspicious_domains()
    analysis = analyze_dataframe(user_df, suspicious_domains)
    app.logger.info("/api/analyze: done, returning JSON")
    return jsonify(analysis)


@app.route("/api/export/csv", methods=["POST"]) 
def export_csv():
    payload = request.get_json(silent=True)
    if not payload or "rows" not in payload:
        return jsonify({"error": "Expected JSON body with 'rows'"}), 400
    df = pd.DataFrame(payload["rows"]) if isinstance(payload["rows"], list) else pd.DataFrame()
    if df.empty:
        return jsonify({"error": "No rows to export"}), 400
    buf = io.StringIO()
    df.to_csv(buf, index=False)
    buf.seek(0)
    return send_file(
        io.BytesIO(buf.getvalue().encode("utf-8")),
        mimetype="text/csv",
        as_attachment=True,
        download_name="analysis.csv",
    )

@app.route("/api/export/excel", methods=["POST"]) 
def export_excel():
    payload = request.get_json(silent=True)
    if not payload or "rows" not in payload:
        return jsonify({"error": "Expected JSON body with 'rows'"}), 400
    df = pd.DataFrame(payload["rows"]) if isinstance(payload["rows"], list) else pd.DataFrame()
    if df.empty:
        return jsonify({"error": "No rows to export"}), 400
    out = io.BytesIO()
    with pd.ExcelWriter(out, engine="openpyxl") as writer:
        df.to_excel(writer, index=False, sheet_name="Results")
    out.seek(0)
    return send_file(
        out,
        mimetype="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        as_attachment=True,
        download_name="analysis.xlsx",
    )


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)


