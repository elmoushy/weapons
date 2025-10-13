# Safe migration for per-device access feature

from django.db import migrations, connection


def check_column_exists(table_name, column_name):
    """
    Returns True if the column exists in the Oracle DB, False otherwise.
    For non-Oracle databases (e.g., SQLite, Postgres), always returns False.
    """
    cursor = connection.cursor()
    vendor = connection.vendor

    # Skip for non-Oracle databases (used in CI/CD)
    if vendor != "oracle":
        print(f"⚠️ Skipping Oracle-specific check_column_exists() on {vendor}.")
        return False

    # Oracle-specific column check
    cursor.execute("""
                   SELECT COUNT(*) FROM user_tab_columns
                   WHERE table_name = UPPER(%s) AND column_name = UPPER(%s)
                   """, [table_name, column_name])
    result = cursor.fetchone()[0] > 0
    print(f"✅ Oracle check_column_exists({table_name}, {column_name}) = {result}")
    return result


def check_table_exists(table_name):
    """
    Returns True if the table exists in Oracle DB, False otherwise.
    Skips gracefully for non-Oracle databases (CI/CD environments).
    """
    cursor = connection.cursor()
    vendor = connection.vendor

    if vendor != "oracle":
        print(f"⚠️ Skipping Oracle-specific check_table_exists() on {vendor}.")
        return False

    cursor.execute("""
                   SELECT COUNT(*) FROM user_tables WHERE table_name = UPPER(%s)
                   """, [table_name])
    result = cursor.fetchone()[0] > 0
    print(f"✅ Oracle check_table_exists({table_name}) = {result}")
    return result


def add_per_device_access_field(apps, schema_editor):
    """Safely add per_device_access field to surveys_survey table."""
    try:
        if not check_column_exists('surveys_survey', 'per_device_access'):
            print("Adding per_device_access field to surveys_survey...")

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
            print("✅ SUCCESS: per_device_access field added successfully.")
        else:
            print("ℹ️ per_device_access field already exists — skipping.")
    except Exception as e:
        print(f"⚠️ Warning while adding per_device_access field: {e}")


def create_device_response_table(apps, schema_editor):
    """Safely create the surveys_device_response table."""
    try:
        if not check_table_exists('surveys_device_response'):
            print("Creating surveys_device_response table...")

            with connection.cursor() as cursor:
                if connection.vendor == 'oracle':
                    try:
                        # Detect ID types dynamically from Oracle tables
                        def get_type_for(table, column):
                            cursor.execute("""
                                           SELECT data_type, data_length, data_precision, data_scale
                                           FROM user_tab_columns
                                           WHERE table_name = UPPER(%s) AND column_name = UPPER(%s)
                                           """, [table, column])
                            t = cursor.fetchone()
                            if not t:
                                return "RAW(16)"
                            data_type, length, prec, scale = t
                            if data_type == "RAW":
                                return f"RAW({int(length)})"
                            if data_type == "NUMBER" and prec:
                                return f"NUMBER({int(prec)})"
                            if data_type == "VARCHAR2":
                                return f"VARCHAR2({int(length)})"
                            return data_type

                        survey_id_type = get_type_for("SURVEYS_SURVEY", "ID")
                        response_id_type = get_type_for("SURVEYS_RESPONSE", "ID")

                        print(f"Detected types: survey_id={survey_id_type}, response_id={response_id_type}")
                    except Exception as e:
                        print(f"⚠️ Warning detecting column types, defaulting to RAW(16): {e}")
                        survey_id_type = response_id_type = "RAW(16)"

                    cursor.execute(f"""
                        CREATE TABLE surveys_device_response (
                            id RAW(16) DEFAULT SYS_GUID() PRIMARY KEY,
                            survey_id {survey_id_type} NOT NULL,
                            device_fingerprint VARCHAR2(64) NOT NULL,
                            ip_address VARCHAR2(45),
                            user_agent CLOB,
                            submitted_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP NOT NULL,
                            response_id {response_id_type},
                            CONSTRAINT fk_device_response_survey FOREIGN KEY (survey_id)
                                REFERENCES surveys_survey (id),
                            CONSTRAINT fk_device_response_response FOREIGN KEY (response_id)
                                REFERENCES surveys_response (id)
                        )
                    """)

                    cursor.execute("""
                                   ALTER TABLE surveys_device_response
                                       ADD CONSTRAINT uk_device_response_survey_fp UNIQUE (survey_id, device_fingerprint)
                                   """)

                    cursor.execute("""
                                   CREATE INDEX surveys_device_fp_idx
                                       ON surveys_device_response (device_fingerprint)
                                   """)

                else:
                    # For CI/CD or other databases
                    cursor.execute("""
                                   CREATE TABLE IF NOT EXISTS surveys_device_response (
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

                    cursor.execute("""
                                   CREATE INDEX IF NOT EXISTS surveys_device_fp_idx
                                       ON surveys_device_response (device_fingerprint)
                                   """)

            print("✅ SUCCESS: surveys_device_response table created.")
        else:
            print("ℹ️ surveys_device_response table already exists — skipping.")
    except Exception as e:
        print(f"⚠️ Warning while creating device response table: {e}")


def reverse_per_device_access_field(apps, schema_editor):
    """Safely remove per_device_access field."""
    try:
        if check_column_exists('surveys_survey', 'per_device_access'):
            print("Removing per_device_access field...")
            with connection.cursor() as cursor:
                cursor.execute("ALTER TABLE surveys_survey DROP COLUMN per_device_access")
            print("✅ SUCCESS: per_device_access removed.")
        else:
            print("ℹ️ per_device_access not found — skipping removal.")
    except Exception as e:
        print(f"⚠️ Warning while removing per_device_access: {e}")


def reverse_device_response_table(apps, schema_editor):
    """Safely remove DeviceResponse table."""
    try:
        if check_table_exists('surveys_device_response'):
            print("Dropping surveys_device_response table...")
            with connection.cursor() as cursor:
                cursor.execute("DROP TABLE surveys_device_response")
            print("✅ SUCCESS: surveys_device_response table dropped.")
        else:
            print("ℹ️ surveys_device_response not found — skipping removal.")
    except Exception as e:
        print(f"⚠️ Warning while removing device_response table: {e}")


class Migration(migrations.Migration):
    dependencies = [
        ('surveys', '0007_survey_status'),
    ]

    operations = [
        migrations.RunPython(
            add_per_device_access_field,
            reverse_per_device_access_field,
            elidable=True,
        ),
        migrations.RunPython(
            create_device_response_table,
            reverse_device_response_table,
            elidable=True,
        ),
    ]
