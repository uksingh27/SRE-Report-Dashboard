import os

# Regions base path — set via REGIONS_BASE_PATH env var for Docker (mount volume there)
REGIONS_BASE_PATH = os.environ.get(
    'REGIONS_BASE_PATH',
    r'C:\Users\upendras\OneDrive - NICE Ltd\SRE_real_Reports\Regions'
)

REGIONS = ["Australia", "Canada", "Fedramp", "Germany", "Japan", "Japan Osaka", "Korea", "UK"]

# File paths
SUSPICIOUS_DOMAINS_FILE = "suspicious_domains.csv"
TENANT_EXCEPTION_FILE = "tenant_exceptions.csv"
SUSPICIOUS_USERNAMES_FILE = "suspicious_usernames.csv"
UPLOAD_FOLDER = os.path.join(os.getcwd(), "uploads")

# Analysis thresholds
ACCESS_KEY_THRESHOLD = 10

# Sheet names
USER_MANAGER_SHEET = "UserManager"
ACCESS_KEY_SHEET = "AccessKeyManagement"
EMAIL_DOMAINS_UPDATE_SHEET = "EmailDomainsUpd_stats"

# Column mappings
USER_MANAGER_COLUMNS = [
    "DATE", "ACTOR_USER_EMAIL", "TENANT_NAME", "USER_NAME", "USER_EMAIL", "ACTIVITY"
]

ACCESS_KEY_COLUMNS = [
    "ACCESS_KEY_ID", "TENANT_NAME", "DATE", "ACTOR_USER_EMAIL", "ACTIVITY"
]

EMAIL_DOMAINS_UPDATE_COLUMNS = [
    "DATE", "ACTOR_USER_EMAIL", "TENANT_NAME", "ACTIVITY"
]
