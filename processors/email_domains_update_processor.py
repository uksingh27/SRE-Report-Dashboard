import pandas as pd
import os
from config import EMAIL_DOMAINS_UPDATE_COLUMNS, SUSPICIOUS_DOMAINS_FILE


def load_suspicious_domains() -> set:
    """Load suspicious domains from CSV file."""
    if not os.path.exists(SUSPICIOUS_DOMAINS_FILE):
        return set()
    
    try:
        suspicious_df = pd.read_csv(SUSPICIOUS_DOMAINS_FILE)
    except Exception:
        return set()
    
    # Use the 'domain' column
    if 'domain' not in suspicious_df.columns and len(suspicious_df.columns) > 0:
        # Fallback to first column if 'domain' column doesn't exist
        domain_col = suspicious_df.columns[0]
    else:
        domain_col = 'domain'
    
    return set(
        domain.strip().lower() for domain in suspicious_df[domain_col].astype(str).fillna("") 
        if domain and domain.strip()
    )


def extract_domains_from_changed_value(changed_value: str) -> list:
    """Extract individual domains from CHANGED_TO_VALUE field."""
    if pd.isna(changed_value) or not changed_value:
        return []
    
    # Remove brackets and split by comma
    cleaned = str(changed_value).strip('[]')
    domains = [d.strip().lower() for d in cleaned.split(',') if d.strip()]
    return domains


def analyze_email_domains_update(email_domains_df: pd.DataFrame) -> dict:
    """Analyze EmailDomainsUpd_stats sheet for suspicious domain matches in CHANGED_TO_VALUE."""
    if email_domains_df.empty:
        return {
            "summary": {"total_updates": 0, "suspicious_matches": 0, "safe_matches": 0, "unique_domains": 0},
            "suspicious_activities": [],
            "all_activities": []
        }
    
    # Load suspicious domains
    suspicious_domains = load_suspicious_domains()
    
    # Ensure required columns exist
    required_columns = ['DATE', 'ACTOR_USERNAME', 'ACTOR_EMAIL', 'TENANT_NAME']
    for col in required_columns:
        if col not in email_domains_df.columns:
            email_domains_df[col] = ""
    
    # Analyze each row for suspicious domain matches
    suspicious_activities = []
    all_activities = []
    unique_domains = set()
    
    for _, row in email_domains_df.iterrows():
        # Extract domains from CHANGED_TO_VALUE
        changed_value = row.get('CHANGED_TO_VALUE', '')
        domains_in_change = extract_domains_from_changed_value(changed_value)
        
        # Add to unique domains set
        unique_domains.update(domains_in_change)
        
        # Check for suspicious domain matches
        has_suspicious = any(domain in suspicious_domains for domain in domains_in_change)
        
        # Prepare activity record
        activity_record = {
            'DATE': row.get('DATE', ''),
            'ACTOR_USERNAME': row.get('ACTOR_USERNAME', ''),
            'ACTOR_EMAIL': row.get('ACTOR_EMAIL', ''),
            'TENANT_NAME': row.get('TENANT_NAME', ''),
            'CHANGED_TO_VALUE': changed_value,
            'DOMAINS_EXTRACTED': ', '.join(domains_in_change),
            'SUSPICIOUS_DOMAINS': ', '.join([d for d in domains_in_change if d in suspicious_domains]),
            'IS_SUSPICIOUS': has_suspicious
        }
        
        # Add to appropriate list
        if has_suspicious:
            suspicious_activities.append(activity_record)
        
        all_activities.append(activity_record)
    
    # Ensure JSON serializable
    suspicious_activities = pd.DataFrame(suspicious_activities).fillna("").to_dict(orient="records")
    all_activities = pd.DataFrame(all_activities).fillna("").to_dict(orient="records")
    
    return {
        "summary": {
            "total_updates": len(email_domains_df),
            "suspicious_matches": len(suspicious_activities),
            "safe_matches": len(all_activities) - len(suspicious_activities),
            "unique_domains": len(unique_domains)
        },
        "suspicious_activities": suspicious_activities,
        "all_activities": all_activities
    }