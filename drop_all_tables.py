#!/usr/bin/env python
"""
Script to drop all tables related to the WeaponpowerCloud backend project from Oracle database.

This script will drop all Django and project-specific tables including:
- Django system tables (django_migrations, django_admin_log, etc.)
- Authentication tables (auth_user, authentication_group, etc.)
- News service tables
- Files endpoint tables
- Surveys tables
- Any other project-related tables

WARNING: This will permanently delete all data in these tables!
"""

import os
import sys
import django
import logging
from datetime import datetime

# Add the project directory to Python path
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

# Setup Django
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'weaponpowercloud_backend.settings')
django.setup()

from django.db import connection, transaction
from django.conf import settings

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(f'drop_tables_{datetime.now().strftime("%Y%m%d_%H%M%S")}.log'),
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger(__name__)


def get_all_project_tables():
    """Get all tables related to this Django project"""
    
    with connection.cursor() as cursor:
        # Get all tables that match our project patterns
        cursor.execute("""
            SELECT table_name 
            FROM user_tables 
            WHERE (
                table_name LIKE 'DJANGO_%' OR
                table_name LIKE 'AUTH_%' OR
                table_name LIKE 'AUTHENTICATION_%' OR
                table_name LIKE 'SURVEYS_%' OR
                table_name LIKE 'WEAPONPOWERCLOUD_%' OR
                table_name IN (
                    'DJANGO_MIGRATIONS',
                    'DJANGO_ADMIN_LOG', 
                    'DJANGO_CONTENT_TYPE',
                    'DJANGO_SESSION',
                    'DJANGO_SITE',
                    'AUTH_PERMISSION',
                    'AUTH_GROUP',
                    'AUTH_GROUP_PERMISSIONS',
                    'AUTH_USER',
                    'AUTH_USER_GROUPS',
                    'AUTH_USER_USER_PERMISSIONS'
                )
            )
            ORDER BY table_name
        """)
        
        return [row[0] for row in cursor.fetchall()]


def get_table_dependencies():
    """Get foreign key dependencies to determine drop order"""
    
    with connection.cursor() as cursor:
        cursor.execute("""
            SELECT 
                a.table_name as child_table,
                a.constraint_name,
                c_pk.table_name as parent_table
            FROM user_constraints a
            JOIN user_constraints c_pk ON a.r_constraint_name = c_pk.constraint_name
            WHERE a.constraint_type = 'R'
            AND (
                a.table_name LIKE 'DJANGO_%' OR
                a.table_name LIKE 'AUTH_%' OR
                a.table_name LIKE 'AUTHENTICATION_%' OR
                a.table_name LIKE 'SURVEYS_%' OR
                a.table_name LIKE 'WEAPONPOWERCLOUD_%'
            )
            ORDER BY a.table_name
        """)
        
        dependencies = {}
        for row in cursor.fetchall():
            child_table, constraint_name, parent_table = row
            if child_table not in dependencies:
                dependencies[child_table] = []
            dependencies[child_table].append({
                'parent': parent_table,
                'constraint': constraint_name
            })
        
        return dependencies


def drop_foreign_key_constraints(tables):
    """Drop all foreign key constraints first"""
    
    logger.info("🔗 Dropping foreign key constraints...")
    
    with connection.cursor() as cursor:
        for table in tables:
            try:
                # Get all foreign key constraints for this table
                cursor.execute("""
                    SELECT constraint_name
                    FROM user_constraints
                    WHERE table_name = %s
                    AND constraint_type = 'R'
                """, [table])
                
                constraints = cursor.fetchall()
                
                for constraint in constraints:
                    constraint_name = constraint[0]
                    try:
                        drop_sql = f"ALTER TABLE {table} DROP CONSTRAINT {constraint_name}"
                        cursor.execute(drop_sql)
                        logger.info(f"   ✅ Dropped constraint {constraint_name} from {table}")
                    except Exception as e:
                        logger.warning(f"   ⚠️  Failed to drop constraint {constraint_name} from {table}: {e}")
                        
            except Exception as e:
                logger.warning(f"   ⚠️  Failed to get constraints for {table}: {e}")


def drop_tables(tables):
    """Drop all tables"""
    
    logger.info("🗑️  Dropping tables...")
    
    dropped_count = 0
    failed_count = 0
    
    with connection.cursor() as cursor:
        for table in tables:
            try:
                # Try to drop the table
                drop_sql = f"DROP TABLE {table} CASCADE CONSTRAINTS"
                cursor.execute(drop_sql)
                logger.info(f"   ✅ Dropped table: {table}")
                dropped_count += 1
                
            except Exception as e:
                logger.error(f"   ❌ Failed to drop table {table}: {e}")
                failed_count += 1
    
    return dropped_count, failed_count


def drop_sequences():
    """Drop sequences related to the project"""
    
    logger.info("🔢 Dropping sequences...")
    
    with connection.cursor() as cursor:
        # Get all sequences that might be related to our project
        cursor.execute("""
            SELECT sequence_name 
            FROM user_sequences 
            WHERE (
                sequence_name LIKE 'DJANGO_%' OR
                sequence_name LIKE 'AUTH_%' OR
                sequence_name LIKE 'AUTHENTICATION_%' OR
                sequence_name LIKE 'SURVEYS_%' OR
                sequence_name LIKE 'WEAPONPOWERCLOUD_%'
            )
            ORDER BY sequence_name
        """)
        
        sequences = cursor.fetchall()
        
        dropped_count = 0
        for sequence in sequences:
            sequence_name = sequence[0]
            try:
                drop_sql = f"DROP SEQUENCE {sequence_name}"
                cursor.execute(drop_sql)
                logger.info(f"   ✅ Dropped sequence: {sequence_name}")
                dropped_count += 1
            except Exception as e:
                logger.warning(f"   ⚠️  Failed to drop sequence {sequence_name}: {e}")
        
        return dropped_count


def confirm_operation():
    """Ask user to confirm the destructive operation"""
    
    print("\n" + "="*80)
    print("⚠️  WARNING: DESTRUCTIVE OPERATION")
    print("="*80)
    print("This script will permanently delete ALL tables and data related to")
    print("the WeaponpowerCloud backend project from your Oracle database.")
    print("")
    print("This includes:")
    print("• Django system tables (migrations, admin log, etc.)")
    print("• User authentication tables and all user data")
    print("• News service tables and all news content")
    print("• Files endpoint tables and all file metadata")
    print("• Survey tables and all survey data")
    print("• Any other project-related tables")
    print("")
    print("THIS OPERATION CANNOT BE UNDONE!")
    print("="*80)
    
    # Show current database info
    print(f"Database: {settings.DATABASES['default']['NAME']}")
    print(f"Host: {settings.DATABASES['default']['HOST']}")
    print(f"User: {settings.DATABASES['default']['USER']}")
    print("")
    
    while True:
        confirm = input("Type 'DROP ALL TABLES' to confirm this operation: ").strip()
        if confirm == 'DROP ALL TABLES':
            return True
        elif confirm.lower() in ['n', 'no', 'cancel', 'exit', 'quit']:
            return False
        else:
            print("Please type 'DROP ALL TABLES' exactly to confirm, or 'no' to cancel.")


def main():
    """Main function to orchestrate the table dropping process"""
    
    print("WeaponpowerCloud Backend - Drop All Tables Script")
    print("="*60)
    
    try:
        # Test database connection
        with connection.cursor() as cursor:
            cursor.execute("SELECT 1 FROM DUAL")
            logger.info("✅ Database connection successful")
    
    except Exception as e:
        logger.error(f"❌ Database connection failed: {e}")
        sys.exit(1)
    
    # Get all project tables
    try:
        tables = get_all_project_tables()
        logger.info(f"📋 Found {len(tables)} project-related tables")
        
        if not tables:
            logger.info("✅ No project tables found to drop")
            return
        
        # Display tables that will be dropped
        print("\nTables that will be dropped:")
        for i, table in enumerate(tables, 1):
            print(f"  {i:2d}. {table}")
        
    except Exception as e:
        logger.error(f"❌ Failed to get project tables: {e}")
        sys.exit(1)
    
    # Confirm operation
    if not confirm_operation():
        logger.info("❌ Operation cancelled by user")
        sys.exit(0)
    
    # Start the dropping process
    logger.info("🚀 Starting table drop process...")
    
    try:
        with transaction.atomic():
            # Step 1: Drop foreign key constraints
            drop_foreign_key_constraints(tables)
            
            # Step 2: Drop tables
            dropped_count, failed_count = drop_tables(tables)
            
            # Step 3: Drop sequences
            sequences_dropped = drop_sequences()
            
            # Summary
            print("\n" + "="*60)
            print("📊 OPERATION SUMMARY")
            print("="*60)
            print(f"Tables dropped successfully: {dropped_count}")
            print(f"Tables failed to drop: {failed_count}")
            print(f"Sequences dropped: {sequences_dropped}")
            print(f"Total tables processed: {len(tables)}")
            
            if failed_count == 0:
                print("✅ All tables dropped successfully!")
                logger.info("✅ Table drop operation completed successfully")
            else:
                print(f"⚠️  {failed_count} tables failed to drop - check logs for details")
                logger.warning(f"⚠️  {failed_count} tables failed to drop")
    
    except Exception as e:
        logger.error(f"❌ Failed during table drop process: {e}")
        print(f"\n❌ Error during operation: {e}")
        sys.exit(1)
    
    # Final verification
    try:
        remaining_tables = get_all_project_tables()
        if remaining_tables:
            print(f"\n⚠️  {len(remaining_tables)} tables still remain:")
            for table in remaining_tables:
                print(f"  - {table}")
        else:
            print("\n✅ All project tables have been successfully removed!")
            
    except Exception as e:
        logger.warning(f"⚠️  Could not verify final state: {e}")


if __name__ == "__main__":
    main()
