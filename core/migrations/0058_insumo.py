from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('core', '0057_requisition_kind_requisitionquoteattachment'),
    ]

    operations = [
        migrations.CreateModel(
            name='Insumo',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('item', models.CharField(max_length=120)),
                ('date', models.DateField()),
                ('quantity', models.DecimalField(decimal_places=2, default=1, max_digits=10)),
                ('name', models.CharField(max_length=200)),
                ('department', models.CharField(blank=True, default='', max_length=120)),
                ('created_at', models.DateTimeField(auto_now_add=True)),
            ],
            options={
                'ordering': ['-date', '-id'],
            },
        ),
    ]
