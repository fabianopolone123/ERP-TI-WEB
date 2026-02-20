from django.db import migrations


def mark_active_users_with_email_flag(apps, schema_editor):
    ERPUser = apps.get_model('core', 'ERPUser')
    ERPUser.objects.filter(is_active=True, is_email_user=False).update(is_email_user=True)


class Migration(migrations.Migration):

    dependencies = [
        ('core', '0044_erpuser_is_hidden_from_users'),
    ]

    operations = [
        migrations.RunPython(mark_active_users_with_email_flag, migrations.RunPython.noop),
    ]

