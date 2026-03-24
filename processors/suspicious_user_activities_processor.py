import pandas as pd
import os
from config import SUSPICIOUS_USERNAMES_FILE, USER_MANAGER_COLUMNS


def extract_domain_from_email(email: str) -> str:
    """Extract domain from email address."""
    if not isinstance(email, str):
        return ""
    email = email.strip()
    if "@" not in email:
        return ""
    return email.split("@", 1)[1].lower()


def load_suspicious_usernames() -> set:
    """Load suspicious usernames from CSV file."""
    suspicious_path = os.path.join(os.getcwd(), SUSPICIOUS_USERNAMES_FILE)
    if not os.path.exists(suspicious_path):
        return set()
    try:
        suspicious_df = pd.read_csv(suspicious_path)
    except Exception:
        return set()
    
    # Use the 'suspicious_username' column
    if 'suspicious_username' not in suspicious_df.columns and len(suspicious_df.columns) > 0:
        # Fallback to first column if 'suspicious_username' column doesn't exist
        username_col = suspicious_df.columns[0]
    else:
        username_col = 'suspicious_username'
    
    return set(
        username.strip().lower() for username in suspicious_df[username_col].astype(str).fillna("") if username and username.strip()
    )


def detect_suspicious_usernames(text: str, suspicious_usernames: set) -> list:
    """Detect suspicious usernames in a text string."""
    if not isinstance(text, str) or not text.strip():
        return []
    
    text_lower = text.lower()
    found_usernames = []
    
    for suspicious_username in suspicious_usernames:
        if suspicious_username in text_lower:
            found_usernames.append(suspicious_username)
    
    return found_usernames


def analyze_suspicious_user_activities(user_df: pd.DataFrame) -> dict:
    """Analyze UserManager sheet for suspicious usernames and return results."""
    if "ACTOR_USER_EMAIL" not in user_df.columns:
        raise ValueError("Column 'ACTOR_USER_EMAIL' not found in sheet 'UserManager'.")
    
    if "USER_EMAIL" not in user_df.columns:
        raise ValueError("Column 'USER_EMAIL' not found in sheet 'UserManager'.")

    # Load suspicious usernames
    suspicious_usernames = load_suspicious_usernames()
    
    # Create result dataframe with requested columns plus analysis
    result_df = user_df.copy()
    
    # Ensure all requested columns exist, fill missing with empty strings
    for col in USER_MANAGER_COLUMNS:
        if col not in result_df.columns:
            result_df[col] = ""
    
    # Add actor domain analysis
    result_df["actor_email_domain"] = result_df["ACTOR_USER_EMAIL"].apply(extract_domain_from_email)
    
    # Detect suspicious usernames in specified columns
    suspicious_columns = ["ACTOR_USERNAME", "ACTOR_USER_EMAIL", "USER_NAME", "USER_EMAIL"]
    result_df["suspicious_usernames_found"] = ""
    result_df["has_suspicious_usernames"] = False
    
    for idx, row in result_df.iterrows():
        found_usernames = []
        for col in suspicious_columns:
            if col in result_df.columns:
                text_value = str(row[col]) if pd.notna(row[col]) else ""
                usernames_in_text = detect_suspicious_usernames(text_value, suspicious_usernames)
                found_usernames.extend(usernames_in_text)
        
        # Remove duplicates and join
        unique_usernames = list(set(found_usernames))
        result_df.at[idx, "suspicious_usernames_found"] = ", ".join(unique_usernames)
        result_df.at[idx, "has_suspicious_usernames"] = len(unique_usernames) > 0
    
    # Select columns for display: requested columns + analysis columns
    display_columns = USER_MANAGER_COLUMNS + ["actor_email_domain", "suspicious_usernames_found", "has_suspicious_usernames"]
    result_rows = result_df[display_columns]
    
    # Replace NaN values with empty strings or appropriate defaults
    result_rows = result_rows.fillna("")
    
    # Convert suspicious columns to boolean for proper JSON serialization
    result_rows["has_suspicious_usernames"] = result_rows["has_suspicious_usernames"].astype(bool)

    # Calculate summary statistics
    total = len(result_rows)
    suspicious_count = int(result_rows["has_suspicious_usernames"].sum())
    safe_count = total - suspicious_count

    # Top suspicious usernames
    top_suspicious = (
        result_rows[result_rows["has_suspicious_usernames"]]
        .groupby("suspicious_usernames_found")
        .size()
        .sort_values(ascending=False)
        .head(10)
    )
    top_suspicious_list = [
        {"usernames": usernames, "count": int(cnt)} for usernames, cnt in top_suspicious.items()
    ]

    # Convert to dict and ensure all values are JSON serializable
    rows_dict = result_rows.to_dict(orient="records")
    for row in rows_dict:
        for key, value in row.items():
            if pd.isna(value):
                row[key] = ""
            elif isinstance(value, (int, float)) and pd.isna(value):
                row[key] = 0

    # Extract suspicious usernames data
    suspicious_usernames_rows = result_df[result_df["has_suspicious_usernames"]].copy()
    suspicious_usernames_data = []
    
    if not suspicious_usernames_rows.empty:
        suspicious_usernames_data = suspicious_usernames_rows[[
            "DATE", "ACTOR_USER_EMAIL", "actor_email_domain", "TENANT_NAME", "USER_NAME", "USER_EMAIL", "suspicious_usernames_found"
        ]].to_dict(orient="records")
        
        # Clean up the data
        for row in suspicious_usernames_data:
            for key, value in row.items():
                if pd.isna(value):
                    row[key] = ""
                elif isinstance(value, (int, float)) and pd.isna(value):
                    row[key] = 0

    return {
        "summary": {
            "total": total,
            "suspicious": suspicious_count,
            "safe": safe_count,
        },
        "topSuspiciousUsernames": top_suspicious_list,
        "suspiciousUsernamesFound": suspicious_usernames_data,
        "rows": rows_dict,
    }
