from django.db import migrations, connection


def create_shared_with_groups_table(apps, schema_editor):
    """Create the SURVEYS_SURVEY_SHARED_WITH_GROUPS / surveys_survey_shared_with_groups table if it is missing.

    - On Oracle we create the upper-case table with sequence, trigger and indexes (id NUMBER PK).
    - On other databases Django normally auto-creates the implicit M2M table, but if for any reason
      it is missing we create a minimal compatible table (id auto, survey_id FK, group_id FK, unique constraint).
    """
    vendor = connection.vendor

    if vendor == 'oracle':
        with connection.cursor() as cursor:
            # Check if table exists
            cursor.execute("""
                SELECT COUNT(*) FROM user_tables 
                WHERE table_name = 'SURVEYS_SURVEY_SHARED_WITH_GROUPS'
            """)
            exists = cursor.fetchone()[0] > 0
            if exists:
                return

            # Create table
            cursor.execute("""
                CREATE TABLE SURVEYS_SURVEY_SHARED_WITH_GROUPS (
                    ID NUMBER(38) PRIMARY KEY,
                    SURVEY_ID RAW(16) NOT NULL,
                    GROUP_ID NUMBER(38) NOT NULL,
                    CONSTRAINT FK_SURVEYS_SHARED_GROUPS_SURVEY2 
                        FOREIGN KEY (SURVEY_ID) REFERENCES SURVEYS_SURVEY(ID) ON DELETE CASCADE,
                    CONSTRAINT FK_SURVEYS_SHARED_GROUPS_GROUP2 
                        FOREIGN KEY (GROUP_ID) REFERENCES AUTHENTICATION_GROUP(ID) ON DELETE CASCADE,
                    CONSTRAINT UK_SURVEYS_SHARED_GROUPS2 UNIQUE (SURVEY_ID, GROUP_ID)
                )
            """)
            # Sequence
            cursor.execute("""
                CREATE SEQUENCE SURVEYS_SURVEY_SHARED_GRP_ID_SEQ
                START WITH 1 INCREMENT BY 1 NOCACHE
            """)
            # Trigger
            cursor.execute("""
                CREATE OR REPLACE TRIGGER SURVEYS_SURVEY_SHARED_GRP_TRG
                BEFORE INSERT ON SURVEYS_SURVEY_SHARED_WITH_GROUPS
                FOR EACH ROW
                BEGIN
                    IF :NEW.ID IS NULL THEN
                        SELECT SURVEYS_SURVEY_SHARED_GRP_ID_SEQ.NEXTVAL INTO :NEW.ID FROM DUAL;
                    END IF;
                END;
            """)
            # Indexes
            for sql in [
                "CREATE INDEX IDX_SURVEYS_SHARED_GRP_SURVEY2 ON SURVEYS_SURVEY_SHARED_WITH_GROUPS(SURVEY_ID)",
                "CREATE INDEX IDX_SURVEYS_SHARED_GRP_GROUP2 ON SURVEYS_SURVEY_SHARED_WITH_GROUPS(GROUP_ID)",
            ]:
                try:
                    cursor.execute(sql)
                except Exception:
                    pass
    else:
        # Non-Oracle: use introspection to verify if table exists (expected lowercase name)
        table_name = 'surveys_survey_shared_with_groups'
        if table_name in connection.introspection.table_names():
            return
        # Create table using generic SQL depending on backend
        with connection.cursor() as cursor:
            if vendor == 'postgresql':
                cursor.execute(
                    """
                    CREATE TABLE surveys_survey_shared_with_groups (
                        id SERIAL PRIMARY KEY,
                        survey_id UUID NOT NULL REFERENCES surveys_survey(id) ON DELETE CASCADE,
                        group_id INTEGER NOT NULL REFERENCES authentication_group(id) ON DELETE CASCADE,
                        UNIQUE (survey_id, group_id)
                    )
                    """
                )
            elif vendor == 'sqlite':
                cursor.execute(
                    """
                    CREATE TABLE surveys_survey_shared_with_groups (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        survey_id CHAR(32) NOT NULL REFERENCES surveys_survey(id) ON DELETE CASCADE,
                        group_id INTEGER NOT NULL REFERENCES authentication_group(id) ON DELETE CASCADE,
                        UNIQUE (survey_id, group_id)
                    )
                    """
                )
            elif vendor == 'mysql':
                cursor.execute(
                    """
                    CREATE TABLE surveys_survey_shared_with_groups (
                        id INT AUTO_INCREMENT PRIMARY KEY,
                        survey_id CHAR(32) NOT NULL,
                        group_id INT NOT NULL,
                        UNIQUE KEY uniq_survey_group (survey_id, group_id),
                        KEY idx_survey (survey_id),
                        KEY idx_group (group_id),
                        CONSTRAINT fk_survey_shared_groups_survey FOREIGN KEY (survey_id) REFERENCES surveys_survey(id) ON DELETE CASCADE,
                        CONSTRAINT fk_survey_shared_groups_group FOREIGN KEY (group_id) REFERENCES authentication_group(id) ON DELETE CASCADE
                    ) ENGINE=InnoDB
                    """
                )
            else:
                # Fallback generic (may need manual adjustment for uncommon backends)
                cursor.execute(
                    """
                    CREATE TABLE surveys_survey_shared_with_groups (
                        id INTEGER PRIMARY KEY,
                        survey_id VARCHAR(64) NOT NULL,
                        group_id INTEGER NOT NULL,
                        UNIQUE (survey_id, group_id)
                    )
                    """
                )


def drop_shared_with_groups_table(apps, schema_editor):
    vendor = connection.vendor
    if vendor == 'oracle':
        with connection.cursor() as cursor:
            for obj in [
                'SURVEYS_SURVEY_SHARED_GRP_TRG',
                'SURVEYS_SURVEY_SHARED_GRP_ID_SEQ',
                'SURVEYS_SURVEY_SHARED_WITH_GROUPS'
            ]:
                try:
                    cursor.execute(f"DROP {'TRIGGER' if obj.endswith('_TRG') else 'SEQUENCE' if obj.endswith('_SEQ') else 'TABLE'} {obj} CASCADE")
                except Exception:
                    pass
    else:
        table_name = 'surveys_survey_shared_with_groups'
        if table_name not in connection.introspection.table_names():
            return
        with connection.cursor() as cursor:
            try:
                cursor.execute(f"DROP TABLE {table_name}")
            except Exception:
                pass


class Migration(migrations.Migration):
    dependencies = [
        ('surveys', '0001_initial'),
        ('authentication', '0001_initial'),
    ]

    operations = [
        migrations.RunPython(create_shared_with_groups_table, reverse_code=drop_shared_with_groups_table),
    ]
