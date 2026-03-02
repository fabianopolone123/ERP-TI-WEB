from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('core', '0060_erpuser_can_view_requisitions_readonly'),
    ]

    operations = [
        migrations.AddField(
            model_name='softwareinventory',
            name='software_serial',
            field=models.CharField(blank=True, default='', max_length=200),
        ),
    ]
