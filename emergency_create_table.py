#!/usr/bin/env python
"""
EMERGENCY PRODUCTION FIX - Create missing SURVEYS_SURVEY_SHARED_WITH_GROUPS table

Run this script when Oracle database comes back online:
python emergency_create_table.py
"""

import os
import sys
import django

# Add the project directory to Python path
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

# Setup Django
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'weaponpowercloud_backend.settings')
django.setup()

from django.db import connection


def create_shared_groups_table():
    """Create SURVEYS_SURVEY_SHARED_WITH_GROUPS table with correct Oracle types"""
    
    print("🚨 EMERGENCY TABLE CREATION - SURVEYS_SURVEY_SHARED_WITH_GROUPS")
    print("=" * 60)
    
    try:
        with connection.cursor() as cursor:
            # Check if already exists
            cursor.execute("""
                SELECT COUNT(*) FROM user_tables 
                WHERE table_name = 'SURVEYS_SURVEY_SHARED_WITH_GROUPS'
            """)
            
            if cursor.fetchone()[0] > 0:
                print("✅ Table already exists - no action needed")
                return True
            
            print("📋 Getting column types from referenced tables...")
            
            # Get SURVEYS_SURVEY.ID type
            cursor.execute("""
                SELECT data_type, data_length, data_precision, data_scale
                FROM user_tab_columns
                WHERE table_name = 'SURVEYS_SURVEY' AND column_name = 'ID'
            """)
            survey_result = cursor.fetchone()
            if not survey_result:
                print("❌ SURVEYS_SURVEY table or ID column not found")
                return False
            
            # Get AUTHENTICATION_GROUP.ID type  
            cursor.execute("""
                SELECT data_type, data_length, data_precision, data_scale
                FROM user_tab_columns
                WHERE table_name = 'AUTHENTICATION_GROUP' AND column_name = 'ID'
            """)
            group_result = cursor.fetchone()
            if not group_result:
                print("❌ AUTHENTICATION_GROUP table or ID column not found")
                return False
            
            # Format Oracle column types
            def format_oracle_type(dt, dl, dp, ds):
                dt = dt.upper()
                if dt in ("CHAR", "NCHAR", "VARCHAR2", "NVARCHAR2", "RAW"):
                    return f"{dt}({int(dl)})"
                elif dt == "NUMBER":
                    if dp is None:
                        return "NUMBER"
                    elif ds is None or int(ds) == 0:
                        return f"NUMBER({int(dp)})"
                    else:
                        return f"NUMBER({int(dp)},{int(ds)})"
                elif dl:
                    return f"{dt}({int(dl)})"
                else:
                    return dt
            
            survey_id_type = format_oracle_type(*survey_result)
            group_id_type = format_oracle_type(*group_result)
            id_type = group_id_type if group_id_type.startswith('NUMBER') else 'NUMBER(19)'
            
            print(f"   Survey ID type: {survey_id_type}")
            print(f"   Group ID type: {group_id_type}")
            print(f"   Table ID type: {id_type}")
            
            print("🔧 Creating table...")
            cursor.execute(f"""
                CREATE TABLE SURVEYS_SURVEY_SHARED_WITH_GROUPS (
                    ID {id_type} PRIMARY KEY,
                    SURVEY_ID {survey_id_type} NOT NULL,
                    GROUP_ID {group_id_type} NOT NULL,
                    CONSTRAINT FK_EMERGENCY_SURVEY
                        FOREIGN KEY (SURVEY_ID) REFERENCES SURVEYS_SURVEY(ID) ON DELETE CASCADE,
                    CONSTRAINT FK_EMERGENCY_GROUP
                        FOREIGN KEY (GROUP_ID) REFERENCES AUTHENTICATION_GROUP(ID) ON DELETE CASCADE,
                    CONSTRAINT UK_EMERGENCY_UNIQUE
                        UNIQUE (SURVEY_ID, GROUP_ID)
                )
            """)
            
            print("🔧 Creating sequence...")
            cursor.execute("""
                CREATE SEQUENCE EMERGENCY_SSG_SEQ
                START WITH 1
                INCREMENT BY 1
                NOCACHE
            """)
            
            print("🔧 Creating trigger...")
            cursor.execute("""
                CREATE OR REPLACE TRIGGER EMERGENCY_SSG_TRG
                BEFORE INSERT ON SURVEYS_SURVEY_SHARED_WITH_GROUPS
                FOR EACH ROW
                BEGIN
                    IF :NEW.ID IS NULL THEN
                        SELECT EMERGENCY_SSG_SEQ.NEXTVAL INTO :NEW.ID FROM DUAL;
                    END IF;
                END;
            """)
            
            print("🔧 Creating indexes...")
            cursor.execute("CREATE INDEX IDX_EMERGENCY_SURVEY ON SURVEYS_SURVEY_SHARED_WITH_GROUPS(SURVEY_ID)")
            cursor.execute("CREATE INDEX IDX_EMERGENCY_GROUP ON SURVEYS_SURVEY_SHARED_WITH_GROUPS(GROUP_ID)")
            
            print("✅ EMERGENCY TABLE CREATION SUCCESSFUL!")
            print("📋 Table: SURVEYS_SURVEY_SHARED_WITH_GROUPS")
            print("📋 Sequence: EMERGENCY_SSG_SEQ") 
            print("📋 Trigger: EMERGENCY_SSG_TRG")
            print("📋 Indexes: IDX_EMERGENCY_SURVEY, IDX_EMERGENCY_GROUP")
            
            return True
            
    except Exception as e:
        print(f"❌ EMERGENCY TABLE CREATION FAILED: {e}")
        return False


def verify_table():
    """Verify the table was created successfully"""
    try:
        with connection.cursor() as cursor:
            cursor.execute("""
                SELECT COUNT(*) FROM user_tables 
                WHERE table_name = 'SURVEYS_SURVEY_SHARED_WITH_GROUPS'
            """)
            exists = cursor.fetchone()[0] > 0
            
            if exists:
                cursor.execute("""
                    SELECT column_name, data_type 
                    FROM user_tab_columns 
                    WHERE table_name = 'SURVEYS_SURVEY_SHARED_WITH_GROUPS'
                    ORDER BY column_id
                """)
                columns = cursor.fetchall()
                print(f"\n✅ VERIFICATION SUCCESSFUL - Table has {len(columns)} columns:")
                for col_name, col_type in columns:
                    print(f"   - {col_name}: {col_type}")
                return True
            else:
                print("\n❌ VERIFICATION FAILED - Table not found")
                return False
                
    except Exception as e:
        print(f"\n❌ VERIFICATION ERROR: {e}")
        return False


if __name__ == "__main__":
    print("Starting emergency table creation...")
    
    try:
        # Test database connection
        with connection.cursor() as cursor:
            cursor.execute("SELECT 1 FROM DUAL")
            print("✅ Database connection successful")
    except Exception as e:
        print(f"❌ Database connection failed: {e}")
        print("💡 Make sure Oracle database is running and accessible")
        sys.exit(1)
    
    # Create table
    success = create_shared_groups_table()
    if success:
        verify_table()
        print("\n🎉 EMERGENCY FIX COMPLETE - Ready for production!")
    else:
        print("\n💥 EMERGENCY FIX FAILED - Check errors above")
        sys.exit(1)
