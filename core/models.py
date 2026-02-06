from django.db import models


class ERPUser(models.Model):
    full_name = models.CharField(max_length=200)
    department = models.CharField(max_length=120, blank=True, default='')
    username = models.CharField(max_length=150, unique=True, null=True, blank=True)
    ad_guid = models.CharField(max_length=64, unique=True, blank=True, default='')
    phone = models.CharField(max_length=30, blank=True, default='')
    mobile = models.CharField(max_length=30, blank=True, default='')
    email = models.EmailField(blank=True, default='')
    extension = models.CharField(max_length=4, blank=True, default='')
    is_active = models.BooleanField(default=True)

    def __str__(self) -> str:
        return self.full_name


class Ticket(models.Model):
    class TicketType(models.TextChoices):
        NAO_CLASSIFICADO = 'nao_classificado', 'Não classificado'
        REQUISICAO = 'requisicao', 'Requisição'
        MELHORIA = 'melhoria', 'Melhoria'
        INCIDENTE = 'incidente', 'Incidente'
        PROGRAMADO = 'programado', 'Programado'

    class Urgency(models.TextChoices):
        NAO_CLASSIFICADO = 'nao_classificado', 'Não classificado'
        PROGRAMADA = 'programada', 'Programada'
        BAIXA = 'baixa', 'Baixa'
        MEDIA = 'media', 'Média'
        ALTA = 'alta', 'Alta'

    class Status(models.TextChoices):
        PENDENTE = 'pendente', 'Pendente'
        EM_ATENDIMENTO = 'em_atendimento', 'Em atendimento'
        FECHADO = 'fechado', 'Fechado'

    title = models.CharField(max_length=200)
    description = models.TextField()
    ticket_type = models.CharField(
        max_length=20,
        choices=TicketType.choices,
        default=TicketType.NAO_CLASSIFICADO,
    )
    urgency = models.CharField(
        max_length=20,
        choices=Urgency.choices,
        default=Urgency.NAO_CLASSIFICADO,
    )
    status = models.CharField(max_length=20, choices=Status.choices, default=Status.PENDENTE)
    created_by = models.ForeignKey(
        'auth.User',
        null=True,
        blank=True,
        on_delete=models.SET_NULL,
        related_name='created_tickets',
    )
    assigned_to = models.ForeignKey(
        ERPUser,
        null=True,
        blank=True,
        on_delete=models.SET_NULL,
        related_name='assigned_tickets',
    )
    collaborators = models.ManyToManyField(
        ERPUser,
        blank=True,
        related_name='collaborating_tickets',
    )
    attachment = models.FileField(upload_to='tickets/', null=True, blank=True)
    resolution = models.TextField(blank=True, default='')
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self) -> str:
        return f'{self.title} ({self.get_status_display()})'


class TicketMessage(models.Model):
    ticket = models.ForeignKey(Ticket, on_delete=models.CASCADE, related_name='messages')
    created_by = models.ForeignKey(
        'auth.User',
        null=True,
        blank=True,
        on_delete=models.SET_NULL,
        related_name='ticket_messages',
    )
    message = models.TextField(blank=True, default='')
    is_internal = models.BooleanField(default=False)
    attachment = models.FileField(upload_to='ticket_messages/', null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self) -> str:
        return f'Mensagem #{self.id} ({self.ticket_id})'


class WhatsAppTemplate(models.Model):
    new_ticket = models.TextField(default='Novo chamado #{id}: {title} | {description}')
    status_update = models.TextField(default='Chamado #{id} atualizado: {status} | {responsavel}')
    new_message = models.TextField(default='Nova mensagem no chamado #{id}: {message}')
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self) -> str:
        return f'WhatsAppTemplate #{self.id}'


class EmailTemplate(models.Model):
    new_ticket_subject = models.CharField(max_length=200, default='[Chamado #{id}] Novo chamado')
    new_ticket_body = models.TextField(default='Novo chamado #{id}: {title}\n{description}')
    status_update_subject = models.CharField(max_length=200, default='[Chamado #{id}] Status atualizado')
    status_update_body = models.TextField(default='Status atual: {status}\nResponsável: {responsavel}')
    new_message_subject = models.CharField(max_length=200, default='[Chamado #{id}] Nova mensagem')
    new_message_body = models.TextField(default='Nova mensagem: {message}')
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self) -> str:
        return f'EmailTemplate #{self.id}'


class WhatsAppNotificationSettings(models.Model):
    send_group_on_new_ticket = models.BooleanField(default=False)
    send_group_on_assignment_new = models.BooleanField(default=True)
    send_group_on_assignment_changed = models.BooleanField(default=True)
    send_group_on_status_pending = models.BooleanField(default=False)
    send_group_on_status_in_progress = models.BooleanField(default=False)
    send_group_on_status_closed = models.BooleanField(default=False)
    send_group_on_message_internal = models.BooleanField(default=False)
    send_group_on_message_user = models.BooleanField(default=False)
    send_individual_on_new_ticket = models.BooleanField(default=False)
    send_individual_on_assignment_new = models.BooleanField(default=True)
    send_individual_on_assignment_changed = models.BooleanField(default=True)
    send_individual_on_status_pending = models.BooleanField(default=True)
    send_individual_on_status_in_progress = models.BooleanField(default=True)
    send_individual_on_status_closed = models.BooleanField(default=True)
    send_individual_on_message_internal = models.BooleanField(default=True)
    send_individual_on_message_user = models.BooleanField(default=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self) -> str:
        return f'WhatsAppNotificationSettings #{self.id}'


class WhatsAppOptOut(models.Model):
    user = models.OneToOneField(ERPUser, on_delete=models.CASCADE, related_name='whatsapp_optout')
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self) -> str:
        return f'WhatsAppOptOut {self.user_id}'
