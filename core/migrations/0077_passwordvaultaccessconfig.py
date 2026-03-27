from django.conf import settings
from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    dependencies = [
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
        ('core', '0076_passwordvaultitem_legacy_schema_repair'),
    ]

    operations = [
        migrations.CreateModel(
            name='PasswordVaultAccessConfig',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('password_hash', models.CharField(blank=True, default='', max_length=255)),
                ('created_at', models.DateTimeField(auto_now_add=True)),
                ('updated_at', models.DateTimeField(auto_now=True)),
                ('updated_by', models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.SET_NULL, related_name='vault_access_configs_updated', to=settings.AUTH_USER_MODEL)),
            ],
            options={
                'verbose_name': 'Configuracao de acesso do cofre',
                'verbose_name_plural': 'Configuracoes de acesso do cofre',
            },
        ),
    ]
