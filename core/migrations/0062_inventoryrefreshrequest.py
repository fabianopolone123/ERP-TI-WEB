from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    dependencies = [
        ('core', '0061_softwareinventory_software_serial'),
    ]

    operations = [
        migrations.CreateModel(
            name='InventoryRefreshRequest',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('hostname', models.CharField(max_length=120)),
                ('status', models.CharField(choices=[('pending', 'Pendente'), ('running', 'Em execução'), ('completed', 'Concluído'), ('failed', 'Falhou')], default='pending', max_length=20)),
                ('requested_at', models.DateTimeField(auto_now_add=True)),
                ('started_at', models.DateTimeField(blank=True, null=True)),
                ('completed_at', models.DateTimeField(blank=True, null=True)),
                ('attempt_count', models.PositiveIntegerField(default=0)),
                ('last_message', models.TextField(blank=True, default='')),
                ('requested_by', models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.SET_NULL, related_name='inventory_refresh_requests', to='auth.user')),
            ],
            options={
                'ordering': ['-requested_at', '-id'],
            },
        ),
    ]
