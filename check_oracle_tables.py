#!/usr/bin/env python
"""
Script to check Oracle database tables for surveys functionality.

This script verifies that all required tables exist in Oracle and can help
diagnose ORA-00942 errors.
"""

import os
import sys
import django
import logging

# Add the project directory to Python path
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

# Setup Django
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'weaponpowercloud_backend.settings')
django.setup()

from django.conf import settings
from django.db import connection
from authentication.models import User, Group, UserGroup

logger = logging.getLogger(__name__)


def check_oracle_tables():
    """Check if all required tables exist in Oracle"""
    
    print("=" * 80)
    print("ORACLE DATABASE TABLE VERIFICATION")
    print("=" * 80)
    
    try:
        with connection.cursor() as cursor:
            # Check for Django tables
            cursor.execute("""
                SELECT table_name 
                FROM user_tables 
                WHERE table_name LIKE 'AUTHENTICATION_%' 
                OR table_name LIKE 'SURVEYS_%'
                OR table_name LIKE 'DJANGO_%'
                ORDER BY table_name
            """)
            
            tables = cursor.fetchall()
            print(f"\n✅ Found {len(tables)} tables in Oracle database:")
            for table in tables:
                print(f"   - {table[0]}")
            
            # Check specifically for the tables used in MySharedSurveysView
            required_tables = [
                'AUTHENTICATION_GROUP', 
                'AUTHENTICATION_USERGROUP',
                'SURVEYS_SURVEY',
                'SURVEYS_QUESTION',
                'SURVEYS_RESPONSE',
                'SURVEYS_ANSWER',
                'SURVEYS_SURVEY_SHARED_WITH',
                'SURVEYS_SURVEY_SHARED_WITH_GROUPS'
            ]
            
            print(f"\n🔍 Checking {len(required_tables)} required tables:")
            missing_tables = []
            
            for table in required_tables:
                cursor.execute(f"SELECT COUNT(*) FROM user_tables WHERE table_name = '{table}'")
                exists = cursor.fetchone()[0] > 0
                status = "✅ EXISTS" if exists else "❌ MISSING"
                print(f"   {table}: {status}")
                if not exists:
                    missing_tables.append(table)
            
            # Check table schemas for existing tables
            print(f"\n📋 Table schemas for existing tables:")
            for table in required_tables:
                cursor.execute(f"SELECT COUNT(*) FROM user_tables WHERE table_name = '{table}'")
                if cursor.fetchone()[0] > 0:
                    cursor.execute(f"""
                        SELECT column_name, data_type, nullable 
                        FROM user_tab_columns 
                        WHERE table_name = '{table}' 
                        ORDER BY column_id
                    """)
                    columns = cursor.fetchall()
                    print(f"\n   📊 {table} ({len(columns)} columns):")
                    for col in columns[:5]:  # Show first 5 columns
                        nullable = "NULL" if col[2] == 'Y' else "NOT NULL"
                        print(f"      - {col[0]}: {col[1]} {nullable}")
                    if len(columns) > 5:
                        print(f"      ... and {len(columns) - 5} more columns")
            
            # Test basic queries that might be causing the issue
            print(f"\n🧪 Testing basic queries:")
            
            # Test User model query
            try:
                user_count = User.objects.count()
                print(f"   ✅ User.objects.count(): {user_count}")
            except Exception as e:
                print(f"   ❌ User.objects.count() failed: {e}")
            
            # Test Group model query
            try:
                group_count = Group.objects.count()
                print(f"   ✅ Group.objects.count(): {group_count}")
            except Exception as e:
                print(f"   ❌ Group.objects.count() failed: {e}")
            
            # Test UserGroup model query
            try:
                usergroup_count = UserGroup.objects.count()
                print(f"   ✅ UserGroup.objects.count(): {usergroup_count}")
            except Exception as e:
                print(f"   ❌ UserGroup.objects.count() failed: {e}")
            
            # Test Survey model query
            try:
                from surveys.models import Survey
                survey_count = Survey.objects.count()
                print(f"   ✅ Survey.objects.count(): {survey_count}")
            except Exception as e:
                print(f"   ❌ Survey.objects.count() failed: {e}")
            
            return missing_tables
                    
    except Exception as e:
        print(f"❌ Error connecting to Oracle database: {e}")
        return None


def test_problematic_query():
    """Test the specific query that's causing the ORA-00942 error"""
    
    print("\n" + "=" * 80)
    print("TESTING PROBLEMATIC QUERY")
    print("=" * 80)
    
    try:
        from surveys.models import Survey
        from django.db.models import Q
        
        # Get a test user
        user = User.objects.first()
        if not user:
            print("❌ No users found in database")
            return
        
        print(f"🧪 Testing with user: {user.email}")
        
        # Test the basic queries one by one
        print("\n1. Testing PUBLIC surveys query...")
        try:
            public_count = Survey.objects.filter(
                Q(visibility='PUBLIC'),
                deleted_at__isnull=True,
                is_active=True
            ).count()
            print(f"   ✅ PUBLIC surveys: {public_count}")
        except Exception as e:
            print(f"   ❌ PUBLIC surveys failed: {e}")
        
        print("\n2. Testing AUTH surveys query...")
        try:
            auth_count = Survey.objects.filter(
                Q(visibility='AUTH'),
                deleted_at__isnull=True,
                is_active=True
            ).count()
            print(f"   ✅ AUTH surveys: {auth_count}")
        except Exception as e:
            print(f"   ❌ AUTH surveys failed: {e}")
        
        print("\n3. Testing PRIVATE shared surveys query...")
        try:
            private_count = Survey.objects.filter(
                Q(visibility='PRIVATE', shared_with=user) & ~Q(creator=user),
                deleted_at__isnull=True,
                is_active=True
            ).count()
            print(f"   ✅ PRIVATE shared surveys: {private_count}")
        except Exception as e:
            print(f"   ❌ PRIVATE shared surveys failed: {e}")
        
        print("\n4. Testing user groups query...")
        try:
            user_groups = user.user_groups.values_list('group', flat=True)
            group_count = user_groups.count()
            print(f"   ✅ User groups: {group_count}")
            
            # Test group-based survey sharing
            if group_count > 0:
                group_surveys_count = Survey.objects.filter(
                    Q(visibility='GROUPS', shared_with_groups__in=user_groups) & ~Q(creator=user),
                    deleted_at__isnull=True,
                    is_active=True
                ).count()
                print(f"   ✅ GROUP shared surveys: {group_surveys_count}")
            else:
                print("   ℹ️  User has no groups")
                
        except Exception as e:
            print(f"   ❌ User groups query failed: {e}")
        
        print("\n5. Testing complete query...")
        try:
            # The complete query from MySharedSurveysView
            public_surveys = Q(visibility='PUBLIC')
            auth_surveys = Q(visibility='AUTH')
            private_shared_surveys = Q(visibility='PRIVATE', shared_with=user) & ~Q(creator=user)
            
            base_query = public_surveys | auth_surveys | private_shared_surveys
            
            # Try without groups first
            complete_count = Survey.objects.filter(
                base_query,
                deleted_at__isnull=True,
                is_active=True
            ).distinct().count()
            print(f"   ✅ Complete query (without groups): {complete_count}")
            
            # Now try with groups
            user_groups = user.user_groups.values_list('group', flat=True)
            if user_groups.exists():
                group_shared_surveys = Q(visibility='GROUPS', shared_with_groups__in=user_groups) & ~Q(creator=user)
                full_query = base_query | group_shared_surveys
                
                full_count = Survey.objects.filter(
                    full_query,
                    deleted_at__isnull=True,
                    is_active=True
                ).distinct().count()
                print(f"   ✅ Complete query (with groups): {full_count}")
            
        except Exception as e:
            print(f"   ❌ Complete query failed: {e}")
            
    except Exception as e:
        print(f"❌ Error testing queries: {e}")


def main():
    """Main function to execute the verification"""
    print("Oracle Database Verification Script")
    
    # Check if we're in a Django environment
    try:
        from django.db import connection
        with connection.cursor() as cursor:
            cursor.execute("SELECT 1 FROM DUAL")
            result = cursor.fetchone()
            print("✅ Oracle database connection successful")
    except Exception as e:
        print(f"❌ Oracle database connection failed: {e}")
        return
    
    # Check tables
    missing_tables = check_oracle_tables()
    
    # Test the problematic query
    test_problematic_query()
    
    # Summary
    print("\n" + "=" * 80)
    print("SUMMARY & RECOMMENDATIONS")
    print("=" * 80)
    
    if missing_tables:
        print(f"❌ Found {len(missing_tables)} missing tables:")
        for table in missing_tables:
            print(f"   - {table}")
        print("\n📋 To fix:")
        print("   1. Run: python manage.py migrate --fake-initial")
        print("   2. Run: python manage.py migrate authentication")
        print("   3. Run: python manage.py migrate surveys")
    else:
        print("✅ All required tables exist")
        print("\n📋 Next steps:")
        print("   1. The ORA-00942 error might be due to:")
        print("      - Missing indexes")
        print("      - Table permission issues")
        print("      - Complex query optimization in Oracle")
        print("   2. Consider implementing the temporary workaround")
        print("      in MySharedSurveysView.get_queryset()")


if __name__ == "__main__":
    main()
