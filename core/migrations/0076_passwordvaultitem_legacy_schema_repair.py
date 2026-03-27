from django.db import migrations


def repair_legacy_vault_schema(apps, schema_editor):
    table_name = 'core_passwordvaultitem'
    connection = schema_editor.connection

    with connection.cursor() as cursor:
        tables = connection.introspection.table_names(cursor)
        if table_name not in tables:
            return

        existing_columns = {
            column.name
            for column in connection.introspection.get_table_description(cursor, table_name)
        }

        statements = []
        if 'account_username_encrypted' not in existing_columns:
            statements.append(
                f"ALTER TABLE {schema_editor.quote_name(table_name)} "
                "ADD COLUMN account_username_encrypted TEXT NOT NULL DEFAULT ''"
            )
        if 'account_url_encrypted' not in existing_columns:
            statements.append(
                f"ALTER TABLE {schema_editor.quote_name(table_name)} "
                "ADD COLUMN account_url_encrypted TEXT NOT NULL DEFAULT ''"
            )

        for statement in statements:
            schema_editor.execute(statement)


class Migration(migrations.Migration):

    dependencies = [
        ('core', '0075_passwordvaultitem'),
    ]

    operations = [
        migrations.RunPython(repair_legacy_vault_schema, migrations.RunPython.noop),
    ]
