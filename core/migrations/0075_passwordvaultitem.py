from django.conf import settings
from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    dependencies = [
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
        ('core', '0074_ticket_close_category'),
    ]

    operations = [
        migrations.CreateModel(
            name='PasswordVaultItem',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('service_name', models.CharField(max_length=160)),
                ('account_username_encrypted', models.TextField(blank=True, default='')),
                ('account_url_encrypted', models.TextField(blank=True, default='')),
                ('password_encrypted', models.TextField()),
                ('notes_encrypted', models.TextField(blank=True, default='')),
                ('created_at', models.DateTimeField(auto_now_add=True)),
                ('updated_at', models.DateTimeField(auto_now=True)),
                ('created_by', models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.SET_NULL, related_name='vault_items_created', to=settings.AUTH_USER_MODEL)),
                ('updated_by', models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.SET_NULL, related_name='vault_items_updated', to=settings.AUTH_USER_MODEL)),
            ],
            options={
                'ordering': ['service_name', 'id'],
            },
        ),
    ]
