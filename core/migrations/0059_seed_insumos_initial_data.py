from datetime import date
from decimal import Decimal

from django.db import migrations


def seed_insumos(apps, schema_editor):
    Insumo = apps.get_model('core', 'Insumo')
    if Insumo.objects.exists():
        return

    rows = [
        ('Bateria', date(2025, 4, 22), Decimal('1.00'), 'Miguel', 'PCP'),
        ('Bateria', date(2025, 4, 28), Decimal('1.00'), 'Ruabi Ferreira', 'Producao'),
        ('Bateria', date(2025, 4, 29), Decimal('1.00'), 'Thiago Novi', 'Producao'),
        ('Bateria', date(2025, 5, 19), Decimal('1.00'), 'Maira Silva', 'RH'),
        ('Bateria', date(2025, 5, 19), Decimal('1.00'), 'Switch', 'Adm 1'),
        ('Bateria', date(2025, 6, 18), Decimal('1.00'), 'Amanda Pollo', 'Orcamentos'),
        ('Bateria', date(2025, 8, 29), Decimal('1.00'), 'Irineu Barbosa', 'Gerencia'),
        ('Bateria', date(2025, 9, 8), Decimal('1.00'), 'Cassia Estevo', 'PCP'),
        ('Bateria', date(2025, 9, 11), Decimal('1.00'), 'Nicolly Fernanda', 'PCP'),
        ('Bateria', date(2025, 10, 9), Decimal('2.00'), 'Wissley', 'Projetos'),
        ('Bateria', date(2025, 10, 15), Decimal('1.00'), 'Luana Keren', 'PCP'),
        ('Mouse', date(2025, 11, 12), Decimal('2.00'), 'Servidor', 'TI'),
        ('Bateria', date(2025, 11, 18), Decimal('1.00'), 'Leticia Reimer', 'Comercial'),
        ('Bateria', date(2025, 11, 24), Decimal('1.00'), 'Marcos Kenji', 'PCP'),
        ('Bateria', date(2025, 12, 16), Decimal('1.00'), 'Bianca Alves', 'Planejamento'),
        ('Bateria', date(2026, 1, 5), Decimal('1.00'), 'Ariadny Gabrielly', 'PCP'),
        ('Teclado', date(2026, 1, 12), Decimal('1.00'), 'Fabio Generoso', 'TI'),
        ('Mouse', date(2026, 1, 12), Decimal('1.00'), 'Fabio Generoso', 'TI'),
        ('Bateria', date(2026, 2, 16), Decimal('1.00'), 'Fabio Generoso', 'TI'),
        ('Bateria', date(2026, 2, 16), Decimal('1.00'), 'Fabio Generoso', 'TI'),
        ('Bateria', date(2026, 2, 25), Decimal('1.00'), 'Mariana Ottaviani', 'Financeiro'),
    ]

    Insumo.objects.bulk_create(
        [
            Insumo(
                item=item,
                date=entry_date,
                quantity=quantity,
                name=name,
                department=department,
            )
            for item, entry_date, quantity, name, department in rows
        ]
    )


def noop_reverse(apps, schema_editor):
    pass


class Migration(migrations.Migration):

    dependencies = [
        ('core', '0058_insumo'),
    ]

    operations = [
        migrations.RunPython(seed_insumos, noop_reverse),
    ]
