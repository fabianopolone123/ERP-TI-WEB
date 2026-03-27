from django.conf import settings
from django.contrib.auth.hashers import make_password
from django.db import migrations


def bootstrap_vault_access_password_config(apps, schema_editor):
    PasswordVaultAccessConfig = apps.get_model('core', 'PasswordVaultAccessConfig')

    config = PasswordVaultAccessConfig.objects.order_by('-updated_at', '-id').first()
    if config and (config.password_hash or '').strip():
        return

    env_hash = (getattr(settings, 'VAULT_ACCESS_PASSWORD_HASH', '') or '').strip()
    env_plain = (getattr(settings, 'VAULT_ACCESS_PASSWORD', '') or '').strip()

    password_hash = ''
    if env_hash:
        password_hash = env_hash
    elif env_plain:
        password_hash = make_password(env_plain)

    if not password_hash:
        return

    if config is None:
        PasswordVaultAccessConfig.objects.create(password_hash=password_hash)
        return

    config.password_hash = password_hash
    config.save()


class Migration(migrations.Migration):

    dependencies = [
        ('core', '0077_passwordvaultaccessconfig'),
    ]

    operations = [
        migrations.RunPython(
            bootstrap_vault_access_password_config,
            migrations.RunPython.noop,
        ),
    ]
