# Safe migration for per-device access feature

from django.db import migrations, models, connection
import django.db.models.deletion
import uuid


def check_column_exists(table_name, column_name):
    """Check if a column exists in a table."""
    with connection.cursor() as cursor:
        if connection.vendor == 'oracle':
            cursor.execute("""
                SELECT COUNT(*) 
                FROM user_tab_columns 
                WHERE table_name = UPPER(%s) 
                AND column_name = UPPER(%s)
            """, [table_name, column_name])
        else:
            cursor.execute("""
                SELECT COUNT(*) 
                FROM information_schema.columns 
                WHERE table_name = %s 
                AND column_name = %s
            """, [table_name, column_name])
        
        return cursor.fetchone()[0] > 0


def check_table_exists(table_name):
    """Check if a table exists."""
    with connection.cursor() as cursor:
        if connection.vendor == 'oracle':
            cursor.execute("""
                SELECT COUNT(*) 
                FROM user_tables 
                WHERE table_name = UPPER(%s)
            """, [table_name])
        else:
            cursor.execute("""
                SELECT COUNT(*) 
                FROM information_schema.tables 
                WHERE table_name = %s
            """, [table_name])
        
        return cursor.fetchone()[0] > 0


def add_per_device_access_field(apps, schema_editor):
    """Safely add per_device_access field to Survey model."""
    
    if not check_column_exists('surveys_survey', 'per_device_access'):
        print("Adding per_device_access field to surveys_survey...")
        
        # Use raw SQL to avoid Django ORM issues
        with connection.cursor() as cursor:
            if connection.vendor == 'oracle':
                cursor.execute("""
                    ALTER TABLE surveys_survey 
                    ADD per_device_access NUMBER(1) DEFAULT 0 NOT NULL
                """)
            else:
                cursor.execute("""
                    ALTER TABLE surveys_survey 
                    ADD COLUMN per_device_access BOOLEAN DEFAULT FALSE NOT NULL
                """)
                
        print("SUCCESS: per_device_access field added successfully")
    else:
        print("SUCCESS: per_device_access field already exists - skipping")


def create_device_response_table(apps, schema_editor):
    """Safely create DeviceResponse table."""
    
    if not check_table_exists('surveys_device_response'):
        print("Creating surveys_device_response table...")
        
        with connection.cursor() as cursor:
            if connection.vendor == 'oracle':
                # Create table for Oracle
                cursor.execute("""
                    CREATE TABLE surveys_device_response (
                        id RAW(16) DEFAULT SYS_GUID() PRIMARY KEY,
                        survey_id RAW(16) NOT NULL,
                        device_fingerprint VARCHAR2(64) NOT NULL,
                        ip_address VARCHAR2(45),
                        user_agent CLOB,
                        submitted_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP NOT NULL,
                        response_id RAW(16),
                        CONSTRAINT fk_device_response_survey 
                            FOREIGN KEY (survey_id) REFERENCES surveys_survey (id),
                        CONSTRAINT fk_device_response_response 
                            FOREIGN KEY (response_id) REFERENCES surveys_response (id)
                    )
                """)
                
                # Create unique constraint
                cursor.execute("""
                    ALTER TABLE surveys_device_response
                    ADD CONSTRAINT uk_device_response_survey_fp 
                    UNIQUE (survey_id, device_fingerprint)
                """)
                
                # Create indexes
                cursor.execute("""
                    CREATE INDEX surveys_device_fp_idx 
                    ON surveys_device_response (device_fingerprint)
                """)
                
            else:
                # Create table for SQLite, PostgreSQL, MySQL
                cursor.execute("""
                    CREATE TABLE surveys_device_response (
                        id CHAR(32) PRIMARY KEY,
                        survey_id CHAR(32) NOT NULL,
                        device_fingerprint VARCHAR(64) NOT NULL,
                        ip_address VARCHAR(45),
                        user_agent TEXT,
                        submitted_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP NOT NULL,
                        response_id CHAR(32),
                        FOREIGN KEY (survey_id) REFERENCES surveys_survey (id),
                        FOREIGN KEY (response_id) REFERENCES surveys_response (id),
                        UNIQUE (survey_id, device_fingerprint)
                    )
                """)
                
                # Create indexes
                cursor.execute("""
                    CREATE INDEX surveys_device_fp_idx 
                    ON surveys_device_response (device_fingerprint)
                """)
                
        print("SUCCESS: surveys_device_response table created successfully")
    else:
        print("SUCCESS: surveys_device_response table already exists - skipping")


def reverse_per_device_access_field(apps, schema_editor):
    """Remove per_device_access field safely."""
    
    if check_column_exists('surveys_survey', 'per_device_access'):
        print("Removing per_device_access field from surveys_survey...")
        
        with connection.cursor() as cursor:
            cursor.execute("ALTER TABLE surveys_survey DROP COLUMN per_device_access")
            
        print("SUCCESS: per_device_access field removed successfully")
    else:
        print("SUCCESS: per_device_access field doesn't exist - skipping removal")


def reverse_device_response_table(apps, schema_editor):
    """Remove DeviceResponse table safely."""
    
    if check_table_exists('surveys_device_response'):
        print("Removing surveys_device_response table...")
        
        with connection.cursor() as cursor:
            cursor.execute("DROP TABLE surveys_device_response")
            
        print("SUCCESS: surveys_device_response table removed successfully")
    else:
        print("SUCCESS: surveys_device_response table doesn't exist - skipping removal")


class Migration(migrations.Migration):

    dependencies = [
        ('surveys', '0007_survey_status'),
    ]

    operations = [
        # Step 1: Safely add the per_device_access field to Survey
        migrations.RunPython(
            add_per_device_access_field,
            reverse_per_device_access_field,
            elidable=True
        ),
        
        # Step 2: Safely create the DeviceResponse table
        migrations.RunPython(
            create_device_response_table,
            reverse_device_response_table,
            elidable=True
        ),
    ]
