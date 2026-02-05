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
