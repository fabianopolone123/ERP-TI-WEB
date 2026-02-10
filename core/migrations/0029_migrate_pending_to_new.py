from django.db import migrations


def move_pending_to_new(apps, schema_editor):
    Ticket = apps.get_model('core', 'Ticket')
    Ticket.objects.filter(status='pendente').update(status='novo')


def noop(apps, schema_editor):
    pass


class Migration(migrations.Migration):

    dependencies = [
        ('core', '0028_alter_ticket_status_tickettimelineevent'),
    ]

    operations = [
        migrations.RunPython(move_pending_to_new, noop),
    ]
