import pandas as pd
import os
from config import SUSPICIOUS_DOMAINS_FILE, USER_MANAGER_COLUMNS


def extract_domain_from_email(email: str) -> str:
    """Extract domain from email address."""
    if not isinstance(email, str):
        return ""
    email = email.strip()
    if "@" not in email:
        return ""
    return email.split("@", 1)[1].lower()


def map_email_provider(domain: str) -> str:
    """Map domain to common email provider."""
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
    """Load suspicious domains from CSV file."""
    suspicious_path = os.path.join(os.getcwd(), SUSPICIOUS_DOMAINS_FILE)
    if not os.path.exists(suspicious_path):
        return set()
    try:
        susp_df = pd.read_csv(suspicious_path)
    except Exception:
        return set()
    
    # Use the 'domain' column
    if 'domain' not in susp_df.columns and len(susp_df.columns) > 0:
        # Fallback to first column if 'domain' column doesn't exist
        domain_col = susp_df.columns[0]
    else:
        domain_col = 'domain'
    
    return set(
        d.strip().lower() for d in susp_df[domain_col].astype(str).fillna("") if d and d.strip()
    )


def analyze_user_manager(user_df: pd.DataFrame) -> dict:
    """Analyze UserManager sheet for suspicious domains and return enhanced results."""
    if "ACTOR_USER_EMAIL" not in user_df.columns:
        raise ValueError("Column 'ACTOR_USER_EMAIL' not found in sheet 'UserManager'.")
    
    if "USER_EMAIL" not in user_df.columns:
        raise ValueError("Column 'USER_EMAIL' not found in sheet 'UserManager'.")

    # Load suspicious domains
    suspicious_domains = load_suspicious_domains()
    
    # Create result dataframe with requested columns plus analysis
    result_df = user_df.copy()
    
    # Ensure all requested columns exist, fill missing with empty strings
    for col in USER_MANAGER_COLUMNS:
        if col not in result_df.columns:
            result_df[col] = ""
    
    # Add actor domain analysis
    result_df["actor_email_domain"] = result_df["ACTOR_USER_EMAIL"].apply(extract_domain_from_email)
    result_df["actor_provider"] = result_df["actor_email_domain"].apply(map_email_provider)
    
    # Add user domain analysis
    result_df["user_email_domain"] = result_df["USER_EMAIL"].apply(extract_domain_from_email)
    result_df["user_provider"] = result_df["user_email_domain"].apply(map_email_provider)
    
    # Flag logic: gmail.com -> special flag; domains in suspicious list -> suspicious
    def compute_flag(domain: str) -> str:
        if domain == "gmail.com":
            return "suspicious - further checks required"
        if domain in suspicious_domains:
            return "suspicious"
        return "safe"

    # Actor domain flags
    result_df["actor_flag"] = result_df["actor_email_domain"].apply(compute_flag)
    result_df["actor_suspicious"] = result_df["actor_flag"].apply(lambda f: f != "safe")
    result_df["actor_severity"] = result_df["actor_flag"].apply(
        lambda f: "medium" if f.startswith("suspicious -") else ("high" if f == "suspicious" else "none")
    )
    
    # User domain flags
    result_df["user_flag"] = result_df["user_email_domain"].apply(compute_flag)
    result_df["user_suspicious"] = result_df["user_flag"].apply(lambda f: f != "safe")
    result_df["user_severity"] = result_df["user_flag"].apply(
        lambda f: "medium" if f.startswith("suspicious -") else ("high" if f == "suspicious" else "none")
    )
    
    # Select columns for display: requested columns + analysis columns
    display_columns = USER_MANAGER_COLUMNS + ["actor_email_domain", "actor_provider", "actor_flag", "actor_suspicious", "actor_severity", "user_email_domain", "user_provider", "user_flag", "user_suspicious", "user_severity"]
    result_rows = result_df[display_columns]
    
    # Replace NaN values with empty strings or appropriate defaults
    result_rows = result_rows.fillna("")
    
    # Convert suspicious columns to boolean for proper JSON serialization
    result_rows["actor_suspicious"] = result_rows["actor_suspicious"].astype(bool)
    result_rows["user_suspicious"] = result_rows["user_suspicious"].astype(bool)

    # Calculate summary statistics for actor domains
    total = len(result_rows)
    actor_suspicious_count = int(result_rows["actor_suspicious"].sum())
    actor_safe_count = total - actor_suspicious_count

    # Calculate summary statistics for user domains
    user_suspicious_count = int(result_rows["user_suspicious"].sum())
    user_safe_count = total - user_suspicious_count

    # Top suspicious actor domains
    top_actor_suspicious = (
        result_rows[result_rows["actor_suspicious"]]
        .groupby("actor_email_domain")
        .size()
        .sort_values(ascending=False)
        .head(10)
    )
    top_actor_suspicious_list = [
        {"domain": dom, "count": int(cnt)} for dom, cnt in top_actor_suspicious.items()
    ]

    # Top suspicious user domains
    top_user_suspicious = (
        result_rows[result_rows["user_suspicious"]]
        .groupby("user_email_domain")
        .size()
        .sort_values(ascending=False)
        .head(10)
    )
    top_user_suspicious_list = [
        {"domain": dom, "count": int(cnt)} for dom, cnt in top_user_suspicious.items()
    ]

    # Provider breakdown for actor domains
    actor_provider_breakdown_series = result_rows.groupby("actor_provider").size().sort_values(ascending=False)
    actor_provider_breakdown = [
        {"provider": prov, "count": int(cnt)} for prov, cnt in actor_provider_breakdown_series.items()
    ]

    # Provider breakdown for user domains
    user_provider_breakdown_series = result_rows.groupby("user_provider").size().sort_values(ascending=False)
    user_provider_breakdown = [
        {"provider": prov, "count": int(cnt)} for prov, cnt in user_provider_breakdown_series.items()
    ]

    # Convert to dict and ensure all values are JSON serializable
    rows_dict = result_rows.to_dict(orient="records")
    for row in rows_dict:
        for key, value in row.items():
            if pd.isna(value):
                row[key] = ""
            elif isinstance(value, (int, float)) and pd.isna(value):
                row[key] = 0

    return {
        "actor_summary": {
            "total": total,
            "suspicious": actor_suspicious_count,
            "safe": actor_safe_count,
        },
        "user_summary": {
            "total": total,
            "suspicious": user_suspicious_count,
            "safe": user_safe_count,
        },
        "topActorSuspiciousDomains": top_actor_suspicious_list,
        "topUserSuspiciousDomains": top_user_suspicious_list,
        "actorProviderBreakdown": actor_provider_breakdown,
        "userProviderBreakdown": user_provider_breakdown,
        "rows": rows_dict,
    }
