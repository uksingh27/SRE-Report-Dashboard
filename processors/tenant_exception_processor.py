import pandas as pd
import os
from config import TENANT_EXCEPTION_FILE


def load_tenant_exceptions() -> set:
    """Load tenant exceptions from CSV file."""
    exception_path = os.path.join(os.getcwd(), TENANT_EXCEPTION_FILE)
    if not os.path.exists(exception_path):
        return set()
    
    try:
        exception_df = pd.read_csv(exception_path)
    except Exception:
        return set()
    
    # Use the 'tenant_name' column
    if 'tenant_name' not in exception_df.columns and len(exception_df.columns) > 0:
        # Fallback to first column if 'tenant_name' column doesn't exist
        tenant_col = exception_df.columns[0]
    else:
        tenant_col = 'tenant_name'
    
    return set(
        tenant.strip() for tenant in exception_df[tenant_col].astype(str).fillna("") 
        if tenant and tenant.strip()
    )


def get_exception_status(tenant_name: str) -> dict:
    """Check if tenant is in exception list and return status."""
    exceptions = load_tenant_exceptions()
    is_exception = tenant_name in exceptions
    
    return {
        "tenant_name": tenant_name,
        "is_exception": is_exception,
        "status": "exception" if is_exception else "normal"
    }
