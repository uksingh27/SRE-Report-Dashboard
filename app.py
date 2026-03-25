from flask import Flask, request, jsonify, send_file, render_template
from werkzeug.utils import secure_filename
from flask_cors import CORS
import os
import io
import uuid
import pandas as pd
import json
from main_processor import get_combined_analysis
from config import UPLOAD_FOLDER, SUSPICIOUS_DOMAINS_FILE, TENANT_EXCEPTION_FILE, SUSPICIOUS_USERNAMES_FILE, REGIONS_BASE_PATH
from processors.region_processor import process_all_regions, get_regions_info


class SafeJSONEncoder(json.JSONEncoder):
    """Custom JSON encoder that handles NaN values."""
    def encode(self, obj):
        if isinstance(obj, float) and pd.isna(obj):
            return '""'
        return super().encode(obj)


app = Flask(__name__)
app.secret_key = "change-me"
app.json_encoder = SafeJSONEncoder
CORS(app, resources={r"/api/*": {"origins": "*"}})

os.makedirs(UPLOAD_FOLDER, exist_ok=True)


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
        app.logger.info("/api/analyze: processing Excel with modular architecture")
        analysis = get_combined_analysis(user_file_path)
        app.logger.info("/api/analyze: done, returning JSON")
        return jsonify(analysis)
    except Exception as exc:
        app.logger.exception("/api/analyze: failed to process Excel")
        return jsonify({"error": f"Failed to process Excel: {exc}"}), 400
    finally:
        try:
            os.remove(user_file_path)
        except Exception:
            pass


@app.route("/api/analyze/suspicious-domains", methods=["POST"])
def api_analyze_suspicious_domains():
    """Analyze suspicious domains from UserManager sheet."""
    app.logger.info("/api/analyze/suspicious-domains: received request")
    if "file" not in request.files:
        return jsonify({"error": "No file provided under form field 'file'"}), 400
    file = request.files["file"]
    if file.filename == "":
        return jsonify({"error": "Empty filename"}), 400

    filename = secure_filename(file.filename)
    user_file_path = os.path.join(UPLOAD_FOLDER, f"{uuid.uuid4()}_{filename}")
    file.save(user_file_path)

    try:
        from processors.user_manager_processor import analyze_user_manager
        user_df = pd.read_excel(user_file_path, sheet_name="UserManager", engine="openpyxl")
        analysis = analyze_user_manager(user_df)
        return jsonify(analysis)
    except Exception as exc:
        app.logger.exception("/api/analyze/suspicious-domains: failed to process Excel")
        return jsonify({"error": f"Failed to process Excel: {exc}"}), 400
    finally:
        try:
            os.remove(user_file_path)
        except Exception:
            pass


@app.route("/api/analyze/access-keys", methods=["POST"])
def api_analyze_access_keys():
    """Analyze access keys from AccessKeyManagement sheet."""
    app.logger.info("/api/analyze/access-keys: received request")
    if "file" not in request.files:
        return jsonify({"error": "No file provided under form field 'file'"}), 400
    file = request.files["file"]
    if file.filename == "":
        return jsonify({"error": "Empty filename"}), 400

    filename = secure_filename(file.filename)
    user_file_path = os.path.join(UPLOAD_FOLDER, f"{uuid.uuid4()}_{filename}")
    file.save(user_file_path)

    try:
        from processors.access_key_processor import analyze_access_keys
        access_key_df = pd.read_excel(user_file_path, sheet_name="AccessKeyManagement", engine="openpyxl")
        analysis = analyze_access_keys(access_key_df)
        return jsonify(analysis)
    except Exception as exc:
        app.logger.exception("/api/analyze/access-keys: failed to process Excel")
        return jsonify({"error": f"Failed to process Excel: {exc}"}), 400
    finally:
        try:
            os.remove(user_file_path)
        except Exception:
            pass


@app.route("/api/analyze/email-domains-update", methods=["POST"])
def api_analyze_email_domains_update():
    """Analyze email domains update from EmailDomainsUpd_stats sheet."""
    app.logger.info("/api/analyze/email-domains-update: received request")
    if "file" not in request.files:
        return jsonify({"error": "No file provided under form field 'file'"}), 400
    file = request.files["file"]
    if file.filename == "":
        return jsonify({"error": "Empty filename"}), 400

    filename = secure_filename(file.filename)
    user_file_path = os.path.join(UPLOAD_FOLDER, f"{uuid.uuid4()}_{filename}")
    file.save(user_file_path)

    try:
        from processors.email_domains_update_processor import analyze_email_domains_update
        email_domains_df = pd.read_excel(user_file_path, sheet_name="EmailDomainsUpd_stats", engine="openpyxl")
        analysis = analyze_email_domains_update(email_domains_df)
        return jsonify(analysis)
    except Exception as exc:
        app.logger.exception("/api/analyze/email-domains-update: failed to process Excel")
        return jsonify({"error": f"Failed to process Excel: {exc}"}), 400
    finally:
        try:
            os.remove(user_file_path)
        except Exception:
            pass


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


@app.route("/api/domains", methods=["GET"])
def get_domains():
    """Get the current list of suspicious domains."""
    try:
        if not os.path.exists(SUSPICIOUS_DOMAINS_FILE):
            return jsonify([])
        
        df = pd.read_csv(SUSPICIOUS_DOMAINS_FILE)
        domains = df['domain'].tolist() if 'domain' in df.columns else []
        return jsonify(domains)
    except Exception as e:
        app.logger.error(f"Error loading domains: {e}")
        return jsonify({"error": "Failed to load domains"}), 500


@app.route("/api/domains", methods=["POST"])
def save_domains():
    """Save the list of suspicious domains."""
    try:
        data = request.get_json()
        domains = data.get('domains', [])
        
        # Validate domains
        if not isinstance(domains, list):
            return jsonify({"error": "Domains must be a list"}), 400
        
        # Clean and validate each domain
        cleaned_domains = []
        for domain in domains:
            if isinstance(domain, str) and domain.strip():
                cleaned_domain = domain.strip().lower()
                if cleaned_domain not in cleaned_domains:  # Remove duplicates
                    cleaned_domains.append(cleaned_domain)
        
        # Save to CSV
        df = pd.DataFrame({'domain': cleaned_domains})
        df.to_csv(SUSPICIOUS_DOMAINS_FILE, index=False)
        
        return jsonify({"message": "Domains saved successfully", "count": len(cleaned_domains)})
    except Exception as e:
        app.logger.error(f"Error saving domains: {e}")
        return jsonify({"error": "Failed to save domains"}), 500


@app.route("/api/tenants", methods=["GET"])
def get_tenants():
    """Get the current list of tenant exceptions."""
    try:
        if not os.path.exists(TENANT_EXCEPTION_FILE):
            return jsonify([])
        
        df = pd.read_csv(TENANT_EXCEPTION_FILE)
        tenants = df['tenant_name'].tolist() if 'tenant_name' in df.columns else []
        # Filter out empty strings
        tenants = [tenant for tenant in tenants if tenant and tenant.strip()]
        return jsonify(tenants)
    except Exception as e:
        app.logger.error(f"Error loading tenants: {e}")
        return jsonify({"error": "Failed to load tenants"}), 500


@app.route("/api/tenants", methods=["POST"])
def save_tenants():
    """Save the list of tenant exceptions."""
    try:
        data = request.get_json()
        tenants = data.get('tenants', [])
        
        # Validate tenants
        if not isinstance(tenants, list):
            return jsonify({"error": "Tenants must be a list"}), 400
        
        # Clean and validate each tenant
        cleaned_tenants = []
        for tenant in tenants:
            if isinstance(tenant, str) and tenant.strip():
                cleaned_tenant = tenant.strip()
                if cleaned_tenant not in cleaned_tenants:  # Remove duplicates
                    cleaned_tenants.append(cleaned_tenant)
        
        # Save to CSV
        df = pd.DataFrame({'tenant_name': cleaned_tenants})
        df.to_csv(TENANT_EXCEPTION_FILE, index=False)
        
        return jsonify({"message": "Tenant exceptions saved successfully", "count": len(cleaned_tenants)})
    except Exception as e:
        app.logger.error(f"Error saving tenants: {e}")
        return jsonify({"error": "Failed to save tenants"}), 500


@app.route("/api/analyze/suspicious-users", methods=["POST"])
def api_analyze_suspicious_users():
    """Analyze uploaded file for suspicious user activities."""
    try:
        if "file" not in request.files:
            return jsonify({"error": "No file uploaded"}), 400
        
        file = request.files["file"]
        if file.filename == "":
            return jsonify({"error": "No file selected"}), 400
        
        if file and file.filename.endswith((".xlsx", ".xls")):
            # Save uploaded file
            filename = secure_filename(file.filename)
            unique_filename = f"{uuid.uuid4()}_{filename}"
            file_path = os.path.join(UPLOAD_FOLDER, unique_filename)
            file.save(file_path)
            
            try:
                # Import the processor
                from processors.suspicious_user_activities_processor import analyze_suspicious_user_activities
                
                # Read UserManager sheet
                user_df = pd.read_excel(file_path, sheet_name="UserManager", engine="openpyxl")
                
                # Analyze suspicious user activities
                result = analyze_suspicious_user_activities(user_df)
                
                return jsonify(result)
                
            except Exception as e:
                app.logger.error(f"Analysis error: {e}")
                return jsonify({"error": f"Analysis failed: {str(e)}"}), 500
            finally:
                # Clean up uploaded file
                if os.path.exists(file_path):
                    os.remove(file_path)
        else:
            return jsonify({"error": "Invalid file type. Please upload an Excel file."}), 400
            
    except Exception as e:
        app.logger.error(f"Upload error: {e}")
        return jsonify({"error": "Upload failed"}), 500


@app.route("/api/usernames", methods=["GET"])
def get_usernames():
    """Get the current list of suspicious usernames."""
    try:
        if not os.path.exists(SUSPICIOUS_USERNAMES_FILE):
            return jsonify([])
        
        df = pd.read_csv(SUSPICIOUS_USERNAMES_FILE)
        usernames = df['suspicious_username'].tolist() if 'suspicious_username' in df.columns else []
        # Filter out empty strings
        usernames = [username for username in usernames if username and username.strip()]
        return jsonify(usernames)
    except Exception as e:
        app.logger.error(f"Error loading usernames: {e}")
        return jsonify({"error": "Failed to load usernames"}), 500


@app.route("/api/usernames", methods=["POST"])
def save_usernames():
    """Save the list of suspicious usernames."""
    try:
        data = request.get_json()
        usernames = data.get('usernames', [])
        
        # Validate usernames
        if not isinstance(usernames, list):
            return jsonify({"error": "Usernames must be a list"}), 400
        
        # Clean and validate each username
        cleaned_usernames = []
        for username in usernames:
            if isinstance(username, str) and username.strip():
                cleaned_username = username.strip()
                if cleaned_username not in cleaned_usernames:  # Remove duplicates
                    cleaned_usernames.append(cleaned_username)
        
        # Save to CSV
        df = pd.DataFrame({'suspicious_username': cleaned_usernames})
        df.to_csv(SUSPICIOUS_USERNAMES_FILE, index=False)
        
        return jsonify({"message": "Suspicious usernames saved successfully", "count": len(cleaned_usernames)})
    except Exception as e:
        app.logger.error(f"Error saving usernames: {e}")
        return jsonify({"error": "Failed to save usernames"}), 500




@app.route("/api/regions", methods=["GET"])
def api_get_regions():
    """Return the list of regions with file counts (no processing)."""
    try:
        info = get_regions_info(REGIONS_BASE_PATH)
        return jsonify(info)
    except Exception as exc:
        app.logger.exception("/api/regions: failed")
        return jsonify({"error": str(exc)}), 500


@app.route("/api/analyze/regions", methods=["POST"])
def api_analyze_regions():
    """Process all region folders and return aggregated analysis per region."""
    app.logger.info("/api/analyze/regions: starting bulk region processing")
    try:
        results = process_all_regions(REGIONS_BASE_PATH)
        app.logger.info("/api/analyze/regions: done")
        return jsonify(results)
    except Exception as exc:
        app.logger.exception("/api/analyze/regions: failed")
        return jsonify({"error": str(exc)}), 500


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)


