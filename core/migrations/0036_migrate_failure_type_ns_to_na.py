from django.db import migrations


def forwards(apps, schema_editor):
    Ticket = apps.get_model('core', 'Ticket')
    TicketWorkLog = apps.get_model('core', 'TicketWorkLog')
    Ticket.objects.filter(last_failure_type='ns').update(last_failure_type='na')
    TicketWorkLog.objects.filter(failure_type='ns').update(failure_type='na')


def backwards(apps, schema_editor):
    Ticket = apps.get_model('core', 'Ticket')
    TicketWorkLog = apps.get_model('core', 'TicketWorkLog')
    Ticket.objects.filter(last_failure_type='na').update(last_failure_type='ns')
    TicketWorkLog.objects.filter(failure_type='na').update(failure_type='ns')


class Migration(migrations.Migration):

    dependencies = [
        ('core', '0035_alter_ticket_last_failure_type_and_more'),
    ]

    operations = [
        migrations.RunPython(forwards, backwards),
    ]
