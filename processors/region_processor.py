import os
import glob
import logging
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed

import pandas as pd

from processors.user_manager_processor import analyze_user_manager
from processors.access_key_processor import analyze_access_keys
from processors.email_domains_update_processor import analyze_email_domains_update
from processors.suspicious_user_activities_processor import analyze_suspicious_user_activities
from config import USER_MANAGER_SHEET, ACCESS_KEY_SHEET, EMAIL_DOMAINS_UPDATE_SHEET, REGIONS

logger = logging.getLogger(__name__)


def get_excel_files(region_path: str) -> list:
    """Return all non-temp Excel files in a region folder."""
    files = []
    for pattern in ("*.xlsx", "*.xls"):
        files.extend(glob.glob(os.path.join(region_path, pattern)))
    # Skip Office temp files (prefixed with ~$)
    return sorted(f for f in files if not os.path.basename(f).startswith("~$"))


def combine_sheets(file_paths: list, sheet_name: str) -> pd.DataFrame:
    """Read a named sheet from every file and concatenate into one DataFrame."""
    frames = []
    for path in file_paths:
        try:
            xl = pd.ExcelFile(path, engine="openpyxl")
            if sheet_name in xl.sheet_names:
                df = pd.read_excel(path, sheet_name=sheet_name, engine="openpyxl")
                if not df.empty:
                    frames.append(df)
        except Exception as exc:
            logger.warning("Could not read sheet '%s' from %s: %s", sheet_name, path, exc)
    return pd.concat(frames, ignore_index=True) if frames else pd.DataFrame()


def process_region(region_name: str, region_path: str) -> dict:
    """Process all Excel files in one region folder and return aggregated results."""
    result = {
        "region": region_name,
        "file_count": 0,
        "files": [],
        "last_updated": datetime.now().isoformat(),
        "error": None,
        "user_manager": None,
        "access_keys": None,
        "email_domains_update": None,
        "suspicious_users": None,
        "summary": {"total": 0, "suspicious": 0, "safe": 0},
    }

    if not os.path.exists(region_path):
        result["error"] = f"Folder not found: {region_path}"
        return result

    file_paths = get_excel_files(region_path)
    result["file_count"] = len(file_paths)
    result["files"] = [os.path.basename(f) for f in file_paths]

    if not file_paths:
        result["error"] = "No Excel files found in this region folder"
        return result

    # Combine all sheets across files for this region
    user_df = combine_sheets(file_paths, USER_MANAGER_SHEET)
    access_key_df = combine_sheets(file_paths, ACCESS_KEY_SHEET)
    email_domains_df = combine_sheets(file_paths, EMAIL_DOMAINS_UPDATE_SHEET)

    combined_suspicious = 0
    combined_total = 0

    # --- UserManager: suspicious domains ---
    if not user_df.empty:
        try:
            result["user_manager"] = analyze_user_manager(user_df)
            actor_s = result["user_manager"].get("actor_summary", {})
            user_s = result["user_manager"].get("user_summary", {})
            combined_suspicious += actor_s.get("suspicious", 0) + user_s.get("suspicious", 0)
            combined_total += actor_s.get("total", 0)
        except Exception as exc:
            logger.error("[%s] UserManager processing failed: %s", region_name, exc)

    # --- UserManager: suspicious usernames (same rows, add to suspicious only) ---
    if not user_df.empty:
        try:
            result["suspicious_users"] = analyze_suspicious_user_activities(user_df)
            sus_s = result["suspicious_users"].get("summary", {})
            combined_suspicious += sus_s.get("suspicious", 0)
        except Exception as exc:
            logger.error("[%s] Suspicious users processing failed: %s", region_name, exc)

    # --- AccessKeyManagement ---
    if not access_key_df.empty:
        try:
            result["access_keys"] = analyze_access_keys(access_key_df)
            ak_s = result["access_keys"].get("summary", {})
            combined_suspicious += ak_s.get("flagged_tenants", 0)
            combined_total += ak_s.get("total_tenants", 0)
        except Exception as exc:
            logger.error("[%s] AccessKeys processing failed: %s", region_name, exc)

    # --- EmailDomainsUpd_stats ---
    if not email_domains_df.empty:
        try:
            result["email_domains_update"] = analyze_email_domains_update(email_domains_df)
            ed_s = result["email_domains_update"].get("summary", {})
            combined_suspicious += ed_s.get("suspicious_matches", 0)
            combined_total += ed_s.get("total_updates", 0)
        except Exception as exc:
            logger.error("[%s] EmailDomains processing failed: %s", region_name, exc)

    result["summary"] = {
        "total": combined_total,
        "suspicious": combined_suspicious,
        "safe": max(0, combined_total - combined_suspicious),
    }
    return result


def process_all_regions(base_path: str) -> dict:
    """Process all 8 regions in parallel (up to 4 at a time)."""
    results = {}
    with ThreadPoolExecutor(max_workers=4) as executor:
        futures = {
            executor.submit(process_region, region, os.path.join(base_path, region)): region
            for region in REGIONS
        }
        for future in as_completed(futures):
            region = futures[future]
            try:
                results[region] = future.result()
            except Exception as exc:
                logger.error("Region %s failed: %s", region, exc)
                results[region] = {
                    "region": region,
                    "error": str(exc),
                    "file_count": 0,
                    "files": [],
                    "summary": {"total": 0, "suspicious": 0, "safe": 0},
                }
    return results


def get_regions_info(base_path: str) -> list:
    """Quick scan — return file counts per region without processing."""
    info = []
    for region in REGIONS:
        region_path = os.path.join(base_path, region)
        if os.path.exists(region_path):
            files = get_excel_files(region_path)
            info.append({"region": region, "file_count": len(files), "exists": True})
        else:
            info.append({"region": region, "file_count": 0, "exists": False})
    return info
