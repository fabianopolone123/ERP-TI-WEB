from django.db import migrations


def rebuild_legacy_passwordvaultitem_table(apps, schema_editor):
    PasswordVaultItem = apps.get_model('core', 'PasswordVaultItem')
    table_name = PasswordVaultItem._meta.db_table
    legacy_table_name = f'{table_name}__legacy_repair'
    connection = schema_editor.connection
    quote = schema_editor.quote_name

    with connection.cursor() as cursor:
        tables = set(connection.introspection.table_names(cursor))
        if table_name not in tables:
            return

        existing_columns = {
            column.name
            for column in connection.introspection.get_table_description(cursor, table_name)
        }
        expected_columns = {
            'id',
            'service_name',
            'account_username_encrypted',
            'account_url_encrypted',
            'password_encrypted',
            'notes_encrypted',
            'created_by_id',
            'updated_by_id',
            'created_at',
            'updated_at',
        }
        legacy_only_columns = {'account_username', 'account_url'}

        needs_rebuild = bool(existing_columns & legacy_only_columns) or not expected_columns.issubset(existing_columns)
        if not needs_rebuild:
            return

        if legacy_table_name in tables:
            schema_editor.execute(f'DROP TABLE {quote(legacy_table_name)}')

        schema_editor.execute(f'ALTER TABLE {quote(table_name)} RENAME TO {quote(legacy_table_name)}')
        schema_editor.create_model(PasswordVaultItem)

        select_sql = f'''
            SELECT
                id,
                service_name,
                {('account_username_encrypted' if 'account_username_encrypted' in existing_columns else "''")} AS account_username_encrypted,
                {('account_username' if 'account_username' in existing_columns else "''")} AS legacy_account_username,
                {('account_url_encrypted' if 'account_url_encrypted' in existing_columns else "''")} AS account_url_encrypted,
                {('account_url' if 'account_url' in existing_columns else "''")} AS legacy_account_url,
                {('password_encrypted' if 'password_encrypted' in existing_columns else "''")} AS password_encrypted,
                {('notes_encrypted' if 'notes_encrypted' in existing_columns else "''")} AS notes_encrypted,
                {('created_by_id' if 'created_by_id' in existing_columns else 'NULL')} AS created_by_id,
                {('updated_by_id' if 'updated_by_id' in existing_columns else 'NULL')} AS updated_by_id,
                {('created_at' if 'created_at' in existing_columns else 'CURRENT_TIMESTAMP')} AS created_at,
                {('updated_at' if 'updated_at' in existing_columns else 'CURRENT_TIMESTAMP')} AS updated_at
            FROM {quote(legacy_table_name)}
            ORDER BY id
        '''
        cursor.execute(select_sql)
        rows = cursor.fetchall()

    from core.vault_crypto import encrypt_vault_text

    insert_rows = []
    for row in rows:
        (
            item_id,
            service_name,
            account_username_encrypted,
            legacy_account_username,
            account_url_encrypted,
            legacy_account_url,
            password_encrypted,
            notes_encrypted,
            created_by_id,
            updated_by_id,
            created_at,
            updated_at,
        ) = row

        username_cipher = (account_username_encrypted or '').strip()
        url_cipher = (account_url_encrypted or '').strip()

        legacy_username = legacy_account_username or ''
        legacy_url = legacy_account_url or ''

        if not username_cipher and legacy_username:
            username_cipher = encrypt_vault_text(legacy_username)
        if not url_cipher and legacy_url:
            url_cipher = encrypt_vault_text(legacy_url)

        insert_rows.append(
            (
                item_id,
                service_name or '',
                username_cipher,
                url_cipher,
                password_encrypted or '',
                notes_encrypted or '',
                created_by_id,
                updated_by_id,
                created_at,
                updated_at,
            )
        )

    if insert_rows:
        with connection.cursor() as cursor:
            cursor.executemany(
                f'''
                INSERT INTO {quote(table_name)} (
                    id,
                    service_name,
                    account_username_encrypted,
                    account_url_encrypted,
                    password_encrypted,
                    notes_encrypted,
                    created_by_id,
                    updated_by_id,
                    created_at,
                    updated_at
                ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                ''',
                insert_rows,
            )

    schema_editor.execute(f'DROP TABLE {quote(legacy_table_name)}')


class Migration(migrations.Migration):

    dependencies = [
        ('core', '0078_bootstrap_vault_access_password_config'),
    ]

    operations = [
        migrations.RunPython(
            rebuild_legacy_passwordvaultitem_table,
            migrations.RunPython.noop,
        ),
    ]
