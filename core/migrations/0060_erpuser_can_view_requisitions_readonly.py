from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('core', '0059_seed_insumos_initial_data'),
    ]

    operations = [
        migrations.AddField(
            model_name='erpuser',
            name='can_view_requisitions_readonly',
            field=models.BooleanField(default=False),
        ),
    ]

