from django.conf import settings
from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    dependencies = [
        ('core', '0075_emprestimo'),
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
    ]

    operations = [
        migrations.CreateModel(
            name='PlanoAtivo',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('nome', models.CharField(max_length=200)),
                ('data_inicio', models.DateField()),
                ('data_fim', models.DateField()),
                ('valor', models.DecimalField(decimal_places=2, default=0, max_digits=12)),
                ('documentacao', models.FileField(blank=True, null=True, upload_to='planos_ativos/')),
                ('created_at', models.DateTimeField(auto_now_add=True)),
                ('updated_at', models.DateTimeField(auto_now=True)),
                ('created_by', models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.SET_NULL, related_name='planos_ativos_criados', to=settings.AUTH_USER_MODEL)),
            ],
            options={
                'ordering': ['data_fim', 'nome', 'id'],
            },
        ),
    ]
