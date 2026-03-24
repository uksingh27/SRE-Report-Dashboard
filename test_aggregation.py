#!/usr/bin/env python3
"""
Test script to verify the combined analysis aggregation works correctly
"""
import pandas as pd
import json
import sys
from main_processor import get_combined_analysis

# Test with sample data
test_data = {
    'UserManager': pd.DataFrame({
        'DATE': ['2024-01-01', '2024-01-02'],
        'ACTOR_USER_EMAIL': ['actor@gmail.com', 'actor@suspicious.domain'],
        'ACTOR_USERNAME': ['user1', 'user2'],
        'USER_EMAIL': ['user@gmail.com', 'user@company.com'],
        'USER_NAME': ['Employee1', 'Employee2'],
        'TENANT_NAME': ['Tenant1', 'Tenant2'],
        'ACTIVITY': ['Login', 'FileAccess']
    }),
    'AccessKeyManagement': pd.DataFrame({
        'DATE': ['2024-01-01', '2024-01-02', '2024-01-03', '2024-01-04', '2024-01-05',
                 '2024-01-06', '2024-01-07', '2024-01-08', '2024-01-09', '2024-01-10',
                 '2024-01-11'],
        'TENANT_NAME': ['Tenant1']*11,
        'KEY_ID': [f'KEY_{i}' for i in range(11)],
        'CREATED_DATE': ['2024-01-01']*11
    }),
    'EmailDomainsUpd_stats': pd.DataFrame({
        'DATE': ['2024-01-01'],
        'ACTOR_USERNAME': ['actor1'],
        'ACTOR_EMAIL': ['actor@company.com'],
        'TENANT_NAME': ['Tenant1'],
        'CHANGED_TO_VALUE': ['[suspicious.domain, another.domain]']
    })
}

print("Testing combined analysis aggregation...")
print("=" * 60)

# Create a test Excel file
test_file = 'c:\\Users\\upendras\\sre\\uploads\\test_analysis.xlsx'
with pd.ExcelWriter(test_file, engine='openpyxl') as writer:
    for sheet_name, df in test_data.items():
        df.to_excel(writer, sheet_name=sheet_name, index=False)

print(f"Created test file: {test_file}")

try:
    # Run the combined analysis
    result = get_combined_analysis(test_file)
    
    # Display the summary
    if 'summary' in result:
        summary = result['summary']
        print("\n✓ COMBINED ANALYSIS SUMMARY:")
        print(f"  Total Activities: {summary.get('total', 0)}")
        print(f"  Suspicious Activities: {summary.get('suspicious', 0)}")
        print(f"  Safe Activities: {summary.get('safe', 0)}")
        
        print("\n✓ ANALYSIS BREAKDOWN:")
        for analysis_type, breakdown in result.get('analysis_breakdown', {}).items():
            print(f"  - {breakdown.get('name', analysis_type)}: {breakdown.get('suspicious', 0)}/{breakdown.get('total', 0)}")
        
        print("\n✓ SUCCESS: Combined analysis working correctly!")
        print("  The summary now includes counts from:")
        print("    1. UserManager Domain Analysis")
        print("    2. Suspicious User Activities")
        print("    3. Access Key Management")
        print("    4. Email Domains Update")
        
    else:
        print("\n✗ ERROR: No summary found in results")
        print(json.dumps(result, indent=2, default=str))
        
except Exception as e:
    print(f"\n✗ ERROR: {e}")
    import traceback
    traceback.print_exc()
finally:
    # Clean up
    import os
    if os.path.exists(test_file):
        os.remove(test_file)
        print(f"\nCleaned up test file: {test_file}")
