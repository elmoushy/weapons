from django.db import migrations, connection


def ensure_shared_with_groups_table(apps, schema_editor):
    """Ensure SURVEYS_SURVEY_SHARED_WITH_GROUPS table exists.

    Fixes ORA-02267 by matching FK column data types to the referenced columns (SURVEYS_SURVEY.ID, AUTHENTICATION_GROUP.ID).
    """
    vendor = connection.vendor
    if vendor == 'oracle':
        def _oracle_col_type(cursor, table_name, column_name):
            cursor.execute(
                """
                SELECT data_type, data_length, data_precision, data_scale
                FROM user_tab_columns
                WHERE table_name = :t AND column_name = :c
                """,
                {"t": table_name.upper(), "c": column_name.upper()},
            )
            row = cursor.fetchone()
            if not row:
                raise RuntimeError(f"Column {table_name}.{column_name} not found for type introspection")
            data_type, data_length, data_precision, data_scale = row
            dt = data_type.upper()
            if dt in ("CHAR", "NCHAR", "VARCHAR2", "NVARCHAR2", "RAW"):
                return f"{dt}({int(data_length)})"
            if dt == "NUMBER":
                if data_precision is None:
                    return "NUMBER"
                if data_scale in (None, 0):
                    return f"NUMBER({int(data_precision)})"
                return f"NUMBER({int(data_precision)},{int(data_scale)})"
            if data_length:
                return f"{dt}({int(data_length)})"
            return dt

        with connection.cursor() as cursor:
            # Already exists?
            cursor.execute("""
                SELECT COUNT(*) FROM user_tables WHERE table_name='SURVEYS_SURVEY_SHARED_WITH_GROUPS'
            """)
            if cursor.fetchone()[0] > 0:
                return

            # Introspect referenced column types
            survey_id_type = _oracle_col_type(cursor, 'SURVEYS_SURVEY', 'ID')
            group_id_type = _oracle_col_type(cursor, 'AUTHENTICATION_GROUP', 'ID')
            # Choose ID type same as group id if numeric, else NUMBER(19)
            id_type = group_id_type if group_id_type.startswith('NUMBER') else 'NUMBER(19)'

            create_sql = f"""
                CREATE TABLE SURVEYS_SURVEY_SHARED_WITH_GROUPS (
                    ID {id_type} PRIMARY KEY,
                    SURVEY_ID {survey_id_type} NOT NULL,
                    GROUP_ID {group_id_type} NOT NULL,
                    CONSTRAINT FK_SSG_SURVEY2 FOREIGN KEY (SURVEY_ID)
                        REFERENCES SURVEYS_SURVEY(ID) ON DELETE CASCADE,
                    CONSTRAINT FK_SSG_GROUP2 FOREIGN KEY (GROUP_ID)
                        REFERENCES AUTHENTICATION_GROUP(ID) ON DELETE CASCADE,
                    CONSTRAINT UK_SSG2 UNIQUE (SURVEY_ID, GROUP_ID)
                )
            """
            cursor.execute(create_sql)
            # Sequence & trigger (ignore if existing names already used earlier)
            for sql in [
                """CREATE SEQUENCE SSG_ID_SEQ START WITH 1 INCREMENT BY 1 NOCACHE""",
                """
                CREATE OR REPLACE TRIGGER SSG_ID_TRG
                BEFORE INSERT ON SURVEYS_SURVEY_SHARED_WITH_GROUPS
                FOR EACH ROW
                BEGIN
                    IF :NEW.ID IS NULL THEN
                        SELECT SSG_ID_SEQ.NEXTVAL INTO :NEW.ID FROM DUAL;
                    END IF;
                END;""",
            ]:
                try:
                    cursor.execute(sql)
                except Exception:
                    pass
            # Indexes
            for sql in [
                "CREATE INDEX IDX_SSG_SURVEY2 ON SURVEYS_SURVEY_SHARED_WITH_GROUPS(SURVEY_ID)",
                "CREATE INDEX IDX_SSG_GROUP2 ON SURVEYS_SURVEY_SHARED_WITH_GROUPS(GROUP_ID)",
            ]:
                try:
                    cursor.execute(sql)
                except Exception:
                    pass
    else:
        table_name = 'surveys_survey_shared_with_groups'
        if table_name in connection.introspection.table_names():
            return
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
                        UNIQUE KEY uniq_survey_group2 (survey_id, group_id),
                        KEY idx_survey2 (survey_id),
                        KEY idx_group2 (group_id),
                        CONSTRAINT fk_survey_shared_groups_survey2 FOREIGN KEY (survey_id) REFERENCES surveys_survey(id) ON DELETE CASCADE,
                        CONSTRAINT fk_survey_shared_groups_group2 FOREIGN KEY (group_id) REFERENCES authentication_group(id) ON DELETE CASCADE
                    ) ENGINE=InnoDB
                    """
                )
            else:
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


def noop_reverse(apps, schema_editor):
    pass


class Migration(migrations.Migration):
    dependencies = [
        ('surveys', '0002_add_missing_shared_with_groups_table'),
        ('authentication', '0001_initial'),
    ]

    operations = [
        migrations.RunPython(ensure_shared_with_groups_table, reverse_code=noop_reverse),
    ]
