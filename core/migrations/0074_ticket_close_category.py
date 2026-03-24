from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    dependencies = [
        ('core', '0073_protocolo_gravacao'),
    ]

    operations = [
        migrations.CreateModel(
            name='TicketCloseCategory',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('name', models.CharField(max_length=120, unique=True)),
                ('created_at', models.DateTimeField(auto_now_add=True)),
            ],
            options={
                'ordering': ['name', 'id'],
            },
        ),
        migrations.AddField(
            model_name='ticket',
            name='close_category',
            field=models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.SET_NULL, related_name='tickets', to='core.ticketclosecategory'),
        ),
    ]
