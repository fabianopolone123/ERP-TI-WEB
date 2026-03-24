from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('core', '0072_pendencia'),
    ]

    operations = [
        migrations.AddField(
            model_name='protocolo',
            name='gravacao',
            field=models.FileField(blank=True, null=True, upload_to='protocolos/gravacoes/'),
        ),
    ]
