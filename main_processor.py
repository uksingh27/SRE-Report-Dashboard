import pandas as pd
import os
from processors.user_manager_processor import analyze_user_manager
from processors.access_key_processor import analyze_access_keys
from processors.email_domains_update_processor import analyze_email_domains_update
from processors.suspicious_user_activities_processor import analyze_suspicious_user_activities
from config import USER_MANAGER_SHEET, ACCESS_KEY_SHEET, EMAIL_DOMAINS_UPDATE_SHEET


def process_excel_file(file_path: str, sheet_name: str = None) -> dict:
    """
    Process Excel file and return analysis results.
    
    Args:
        file_path: Path to Excel file
        sheet_name: Specific sheet to process (None for all sheets)
    
    Returns:
        Dictionary with analysis results
    """
    try:
        # Read Excel file
        excel_file = pd.ExcelFile(file_path)
        available_sheets = excel_file.sheet_names
        
        results = {
            "user_manager": None,
            "access_keys": None,
            "email_domains_update": None,
            "suspicious_users": None,
            "available_sheets": available_sheets
        }
        
        # Process UserManager sheet (existing functionality)
        if USER_MANAGER_SHEET in available_sheets:
            user_df = pd.read_excel(file_path, sheet_name=USER_MANAGER_SHEET, engine="openpyxl")
            results["user_manager"] = analyze_user_manager(user_df)
            # Also process for suspicious user activities
            results["suspicious_users"] = analyze_suspicious_user_activities(user_df)
        
        # Process AccessKeyManagement sheet
        if ACCESS_KEY_SHEET in available_sheets:
            access_key_df = pd.read_excel(file_path, sheet_name=ACCESS_KEY_SHEET, engine="openpyxl")
            results["access_keys"] = analyze_access_keys(access_key_df)
        
        # Process EmailDomainsUpd_stats sheet
        if EMAIL_DOMAINS_UPDATE_SHEET in available_sheets:
            email_domains_df = pd.read_excel(file_path, sheet_name=EMAIL_DOMAINS_UPDATE_SHEET, engine="openpyxl")
            results["email_domains_update"] = analyze_email_domains_update(email_domains_df)
        
        return results
        
    except Exception as e:
        raise Exception(f"Failed to process Excel file: {str(e)}")


def get_combined_analysis(file_path: str) -> dict:
    """
    Get combined analysis results for dashboard display.
    Aggregates suspicious counts from all processors.
    """
    results = process_excel_file(file_path)
    
    # Initialize combined summary
    combined_suspicious = 0
    combined_total = 0
    combined_safe = 0
    
    # Aggregate counts from all processors
    analysis_breakdown = {}
    
    # User Manager Analysis (domains + user activities combined)
    if results["user_manager"]:
        actor_summary = results["user_manager"].get("actor_summary", {})
        user_summary = results["user_manager"].get("user_summary", {})
        actor_suspicious = actor_summary.get("suspicious", 0)
        user_suspicious = user_summary.get("suspicious", 0)
        um_total = actor_summary.get("total", 0)
        um_suspicious = actor_suspicious + user_suspicious

        combined_suspicious += um_suspicious
        combined_total += um_total

        analysis_breakdown["user_manager_domains"] = {
            "total": um_total,
            "suspicious": um_suspicious,
            "name": "UserManager - Domain Analysis"
        }

    # Suspicious User Activities (same UserManager rows — add to suspicious count only, not total)
    if results["suspicious_users"]:
        sus_summary = results["suspicious_users"].get("summary", {})
        sus_suspicious = sus_summary.get("suspicious", 0)
        sus_total = sus_summary.get("total", 0)

        combined_suspicious += sus_suspicious
        # Do NOT add sus_total to combined_total: these are the same UserManager rows already counted above

        analysis_breakdown["suspicious_users"] = {
            "total": sus_total,
            "suspicious": sus_suspicious,
            "name": "Suspicious User Activities"
        }
    
    # Access Keys Analysis
    if results["access_keys"]:
        ak_summary = results["access_keys"].get("summary", {})
        ak_suspicious = ak_summary.get("suspicious", 0)
        ak_total = ak_summary.get("total", 0)
        
        combined_suspicious += ak_suspicious
        combined_total += ak_total
        
        analysis_breakdown["access_keys"] = {
            "total": ak_total,
            "suspicious": ak_suspicious,
            "name": "Access Key Management"
        }
    
    # Email Domains Update Analysis
    if results["email_domains_update"]:
        ed_summary = results["email_domains_update"].get("summary", {})
        ed_suspicious = ed_summary.get("suspicious_matches", 0)
        ed_total = ed_summary.get("total_updates", 0)
        
        combined_suspicious += ed_suspicious
        combined_total += ed_total
        
        analysis_breakdown["email_domains_update"] = {
            "total": ed_total,
            "suspicious": ed_suspicious,
            "name": "Email Domains Update"
        }
    
    combined_safe = combined_total - combined_suspicious
    
    # Return UserManager results as primary for display, but with updated summary
    if results["user_manager"]:
        primary_results = results["user_manager"].copy()
        primary_results["summary"] = {
            "total": combined_total,
            "suspicious": combined_suspicious,
            "safe": combined_safe
        }
        primary_results["analysis_breakdown"] = analysis_breakdown
        primary_results["additional_analyses"] = {
            "access_keys": results["access_keys"],
            "email_domains_update": results["email_domains_update"],
            "suspicious_users": results["suspicious_users"]
        }
        return primary_results
    
    # Fallback if UserManager not available
    return {
        "summary": {"total": combined_total, "suspicious": combined_suspicious, "safe": combined_safe},
        "analysis_breakdown": analysis_breakdown,
        "topSuspiciousDomains": [],
        "providerBreakdown": [],
        "rows": [],
        "additional_analyses": {
            "access_keys": results["access_keys"],
            "email_domains_update": results["email_domains_update"],
            "suspicious_users": results["suspicious_users"]
        }
    }

