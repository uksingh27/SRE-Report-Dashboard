import pandas as pd
from config import ACCESS_KEY_THRESHOLD, ACCESS_KEY_COLUMNS
from processors.tenant_exception_processor import load_tenant_exceptions


def analyze_access_keys(access_key_df: pd.DataFrame) -> dict:
    """Analyze AccessKeyManagement sheet for high access key counts per tenant with exception handling."""
    if access_key_df.empty:
        return {
            "summary": {"total_tenants": 0, "flagged_tenants": 0, "exception_tenants": 0},
            "flagged_tenants": [],
            "suspicious_activities": [],
            "all_activities": []
        }
    
    # Load tenant exceptions
    tenant_exceptions = load_tenant_exceptions()
    
    # Count unique access keys per tenant
    tenant_key_counts = access_key_df.groupby('TENANT_NAME')['ACCESS_KEY_ID'].nunique().reset_index()
    tenant_key_counts.columns = ['TENANT_NAME', 'ACCESS_KEY_COUNT']
    
    # Flag tenants with more than threshold access keys
    high_key_tenants = tenant_key_counts[tenant_key_counts['ACCESS_KEY_COUNT'] > ACCESS_KEY_THRESHOLD]
    
    # Separate flagged tenants (excluding exceptions) from exception tenants
    flagged_tenants = []
    exception_tenants = []
    
    for _, row in high_key_tenants.iterrows():
        tenant_name = row['TENANT_NAME']
        count = row['ACCESS_KEY_COUNT']
        
        if tenant_name in tenant_exceptions:
            exception_tenants.append({
                "tenant_name": tenant_name,
                "access_key_count": int(count),
                "status": "exception"
            })
        else:
            flagged_tenants.append({
                "tenant_name": tenant_name,
                "access_key_count": int(count),
                "status": "suspicious"
            })
    
    # Prepare suspicious activities (from flagged tenants only)
    suspicious_activities = []
    if flagged_tenants:
        suspicious_tenant_names = [t["tenant_name"] for t in flagged_tenants]
        suspicious_df = access_key_df[access_key_df['TENANT_NAME'].isin(suspicious_tenant_names)]
        
        requested_columns = ['DATE', 'ACTOR_USERNAME', 'ACTOR_USER_EMAIL', 'TENANT_NAME']
        for col in requested_columns:
            if col not in suspicious_df.columns:
                suspicious_df[col] = ""
        
        suspicious_activities = suspicious_df[requested_columns].fillna("").to_dict(orient="records")
    
    # Prepare all activities (excluding exception tenants)
    requested_columns = ['DATE', 'ACTOR_USERNAME', 'ACTOR_USER_EMAIL', 'TENANT_NAME']
    for col in requested_columns:
        if col not in access_key_df.columns:
            access_key_df[col] = ""
    
    # Filter out exception tenants from all activities
    non_exception_df = access_key_df[~access_key_df['TENANT_NAME'].isin(tenant_exceptions)]
    all_activities = non_exception_df[requested_columns].fillna("").to_dict(orient="records")
    
    return {
        "summary": {
            "total_tenants": len(tenant_key_counts),
            "flagged_tenants": len(flagged_tenants),
            "exception_tenants": len(exception_tenants),
            "non_exception_tenants": len(tenant_key_counts) - len(exception_tenants)
        },
        "flagged_tenants": flagged_tenants,
        "exception_tenants": exception_tenants,
        "suspicious_activities": suspicious_activities,
        "all_activities": all_activities
    }
