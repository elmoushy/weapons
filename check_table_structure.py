#!/usr/bin/env python
import os
import sys
import django

# Add the project path to the Python path
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

# Set up Django environment
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'weaponpowercloud_backend.settings')
django.setup()

from django.db import connection

def check_table_structure():
    with connection.cursor() as cursor:
        # Check the structure of the surveys_public_access_token table
        cursor.execute("""
            SELECT column_name, data_type, nullable, data_length 
            FROM user_tab_columns 
            WHERE table_name = 'SURVEYS_PUBLIC_ACCESS_TOKEN'
            ORDER BY column_id
        """)
        
        columns = cursor.fetchall()
        print("Table structure for SURVEYS_PUBLIC_ACCESS_TOKEN:")
        print("-" * 60)
        for col in columns:
            column_name, data_type, nullable, data_length = col
            print(f"{column_name:<30} {data_type:<15} {nullable:<10} {data_length}")

if __name__ == "__main__":
    check_table_structure()
