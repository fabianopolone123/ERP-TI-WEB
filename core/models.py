import re

from django.db import models, transaction


class ERPUser(models.Model):
    full_name = models.CharField(max_length=200)
    department = models.CharField(max_length=120, blank=True, default='')
    username = models.CharField(max_length=150, unique=True, null=True, blank=True)
    ad_guid = models.CharField(max_length=64, unique=True, blank=True, default='')
    phone = models.CharField(max_length=30, blank=True, default='')
    mobile = models.CharField(max_length=30, blank=True, default='')
    email = models.EmailField(blank=True, default='')
    extension = models.CharField(max_length=4, blank=True, default='')
    is_email_user = models.BooleanField(default=False)
    is_manual = models.BooleanField(default=False)
    is_active = models.BooleanField(default=True)
    is_hidden_from_users = models.BooleanField(default=False)
    email_usage = models.CharField(max_length=40, blank=True, default='')
    email_last_sign_in = models.CharField(max_length=40, blank=True, default='')

    def __str__(self) -> str:
        return self.full_name


class EmailAlias(models.Model):
    user = models.ForeignKey(ERPUser, on_delete=models.CASCADE, related_name='email_aliases')
    email = models.EmailField()
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        unique_together = ('user', 'email')
        ordering = ['email']

    def __str__(self) -> str:
        return f'{self.user.full_name} - {self.email}'


class EmailAccount(models.Model):
    full_name = models.CharField(max_length=200, blank=True, default='')
    email = models.EmailField(unique=True)
    aliases = models.TextField(blank=True, default='')
    email_usage = models.CharField(max_length=80, blank=True, default='')
    email_last_sign_in = models.CharField(max_length=80, blank=True, default='')
    status = models.CharField(max_length=40, blank=True, default='')
    is_active = models.BooleanField(default=True)
    source = models.CharField(max_length=40, blank=True, default='json')
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ['full_name', 'email']

    def __str__(self) -> str:
        return self.email


class Equipment(models.Model):
    tag_code = models.CharField(max_length=80, blank=True, default='')
    sector = models.CharField(max_length=120, blank=True, default='')
    user = models.CharField(max_length=200, blank=True, default='')
    hostname = models.CharField(max_length=120, blank=True, default='')
    equipment = models.CharField(max_length=120, blank=True, default='')
    model = models.CharField(max_length=120, blank=True, default='')
    brand = models.CharField(max_length=120, blank=True, default='')
    serial = models.CharField(max_length=120, blank=True, default='')
    bios_uuid = models.CharField(max_length=120, blank=True, default='')
    bios_serial = models.CharField(max_length=120, blank=True, default='')
    baseboard_serial = models.CharField(max_length=120, blank=True, default='')
    mac_addresses = models.TextField(blank=True, default='')
    hostname_aliases = models.TextField(blank=True, default='')
    needs_reconciliation = models.BooleanField(default=False)
    memory = models.CharField(max_length=60, blank=True, default='')
    processor = models.CharField(max_length=120, blank=True, default='')
    generation = models.CharField(max_length=60, blank=True, default='')
    hd = models.CharField(max_length=120, blank=True, default='')
    mod_hd = models.CharField(max_length=120, blank=True, default='')
    windows = models.CharField(max_length=120, blank=True, default='')
    alimentacao = models.CharField(max_length=120, blank=True, default='')
    observacao = models.TextField(blank=True, default='')
    inventory_source = models.CharField(max_length=40, blank=True, default='')
    last_inventory_at = models.DateTimeField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self) -> str:
        return f'{self.equipment} - {self.user}'





def _extract_equipment_tag_number(tag_code: str) -> int | None:
    raw = (tag_code or '').strip()
    if not raw:
        return None
    match = re.search(r'(\d+)$', raw)
    if not match:
        return None
    try:
        number = int(match.group(1))
    except ValueError:
        return None
    return number if number > 0 else None


def _format_equipment_tag_number(number: int, width: int = 3) -> str:
    width = max(1, int(width or 1))
    return str(int(number)).zfill(width)


def next_equipment_tag_code() -> str:
    numbers = sorted(
        n for n in (_extract_equipment_tag_number(item.tag_code) for item in Equipment.objects.only('tag_code')) if n
    )
    expected = 1
    for number in numbers:
        if number != expected:
            break
        expected += 1
    return str(expected)


@transaction.atomic
def resequence_equipment_tag_codes() -> int:
    equipments = list(Equipment.objects.all().order_by('id'))
    if not equipments:
        return 0
    width = max(3, len(str(len(equipments))))
    changed = []
    for idx, equipment in enumerate(equipments, start=1):
        tag_code = _format_equipment_tag_number(idx, width=width)
        if (equipment.tag_code or '').strip() != tag_code:
            equipment.tag_code = tag_code
            changed.append(equipment)
    if changed:
        Equipment.objects.bulk_update(changed, ['tag_code'])
    return len(changed)

class SoftwareInventory(models.Model):
    equipment = models.ForeignKey(
        Equipment,
        null=True,
        blank=True,
        on_delete=models.SET_NULL,
        related_name='software_items',
    )
    hostname = models.CharField(max_length=120, blank=True, default='')
    sector = models.CharField(max_length=120, blank=True, default='')
    user = models.CharField(max_length=200, blank=True, default='')
    software_name = models.CharField(max_length=250)
    version = models.CharField(max_length=120, blank=True, default='')
    vendor = models.CharField(max_length=200, blank=True, default='')
    install_date = models.CharField(max_length=40, blank=True, default='')
    source = models.CharField(max_length=40, blank=True, default='')
    collected_at = models.DateTimeField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self) -> str:
        return f'{self.hostname} - {self.software_name}'


class Requisition(models.Model):
    class Status(models.TextChoices):
        PENDING_APPROVAL = 'pending_approval', 'Pendente de aprovação'
        APPROVED = 'approved', 'Aprovado'
        REJECTED = 'rejected', 'Reprovado'
        RECEIVED = 'received', 'Recebido'

    title = models.CharField(max_length=200, blank=True, default='')
    request = models.CharField(max_length=300)
    status = models.CharField(max_length=30, choices=Status.choices, default=Status.PENDING_APPROVAL)
    quantity = models.PositiveIntegerField(default=1)
    unit_value = models.DecimalField(max_digits=12, decimal_places=2, default=0)
    total_value = models.DecimalField(max_digits=12, decimal_places=2, default=0)
    requested_at = models.DateField(null=True, blank=True)
    approved_at = models.DateField(null=True, blank=True)
    received_at = models.DateField(null=True, blank=True)
    invoice = models.CharField(max_length=120, blank=True, default='')
    approved_by_2 = models.CharField(max_length=200, blank=True, default='')
    req_type = models.CharField(max_length=120, blank=True, default='')
    location = models.CharField(max_length=120, blank=True, default='')
    link = models.URLField(blank=True, default='')
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def save(self, *args, **kwargs):
        self.total_value = (self.quantity or 0) * (self.unit_value or 0)
        super().save(*args, **kwargs)

    def __str__(self) -> str:
        return f'#{self.id} - {self.request}'

    @property
    def code(self) -> str:
        if not self.id:
            return 'TI - 0000'
        return f'TI - {self.id:04d}'


class RequisitionQuote(models.Model):
    requisition = models.ForeignKey(Requisition, on_delete=models.CASCADE, related_name='quotes')
    parent = models.ForeignKey(
        'self',
        null=True,
        blank=True,
        on_delete=models.SET_NULL,
        related_name='subquotes',
    )
    name = models.CharField(max_length=300)
    quantity = models.PositiveIntegerField(default=1)
    value = models.DecimalField(max_digits=12, decimal_places=2, default=0)
    freight = models.DecimalField(max_digits=12, decimal_places=2, default=0)
    is_selected = models.BooleanField(default=False)
    photo = models.ImageField(upload_to='requisitions/quotes/', null=True, blank=True)
    link = models.URLField(blank=True, default='')
    payment_terms = models.TextField(blank=True, default='')
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self) -> str:
        return f'{self.requisition_id} - {self.name}'


class AccessFolder(models.Model):
    name = models.CharField(max_length=200)
    path = models.CharField(max_length=500)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self) -> str:
        return self.name


class AccessGroup(models.Model):
    folder = models.ForeignKey(AccessFolder, on_delete=models.CASCADE, related_name='groups')
    name = models.CharField(max_length=200)
    access_level = models.CharField(
        max_length=20,
        choices=[('leitura', 'Leitura'), ('leitura_escrita', 'Leitura e escrita')],
        default='leitura',
    )

    def __str__(self) -> str:
        return f'{self.folder.name} - {self.name}'


class AccessMember(models.Model):
    group = models.ForeignKey(AccessGroup, on_delete=models.CASCADE, related_name='members')
    name = models.CharField(max_length=200)
    username = models.CharField(max_length=150, blank=True, default='')

    def __str__(self) -> str:
        return f'{self.group.name} - {self.name}'


class Dica(models.Model):
    class Category(models.TextChoices):
        GERAL = 'geral', 'Geral'
        RESOLUCAO = 'resolucao', 'Resolução de problema'
        ACESSO = 'acesso', 'Acesso / permissão'
        CONFIGURACAO = 'configuracao', 'Configuração'

    category = models.CharField(max_length=20, choices=Category.choices, default=Category.GERAL)
    title = models.CharField(max_length=200)
    content = models.TextField()
    attachment = models.FileField(upload_to='dicas/', null=True, blank=True)
    created_by = models.ForeignKey(
        'auth.User',
        null=True,
        blank=True,
        on_delete=models.SET_NULL,
        related_name='dicas_criadas',
    )
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self) -> str:
        return self.title


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
        NOVO = 'novo', 'Novo'
        PENDENTE = 'pendente', 'Pendente'
        PROGRAMADO = 'programado', 'Programado'
        EM_ATENDIMENTO = 'em_atendimento', 'Em atendimento'
        FECHADO = 'fechado', 'Fechado'

    class FailureType(models.TextChoices):
        NA = 'na', 'N/A'
        EQUIPAMENTO = 'equipamento', 'Equipamento'
        SOFTWARE = 'software', 'Software'
        HUMANA = 'humana', 'Falha humana'

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
    status = models.CharField(max_length=20, choices=Status.choices, default=Status.NOVO)
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
    historical_attendants = models.ManyToManyField(
        ERPUser,
        blank=True,
        related_name='handled_tickets',
    )
    attachment = models.FileField(upload_to='tickets/', null=True, blank=True)
    resolution = models.TextField(blank=True, default='')
    current_cycle_started_at = models.DateTimeField(null=True, blank=True)
    last_failure_type = models.CharField(max_length=20, choices=FailureType.choices, blank=True, default='')
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


class TicketTimelineEvent(models.Model):
    class EventType(models.TextChoices):
        CREATED = 'created', 'Criado'
        STATUS_CHANGED = 'status_changed', 'Status alterado'
        ASSIGNED = 'assigned', 'Atribuído'
        UNASSIGNED = 'unassigned', 'Desatribuído'
        REOPENED = 'reopened', 'Reaberto'

    ticket = models.ForeignKey(Ticket, on_delete=models.CASCADE, related_name='timeline_events')
    event_type = models.CharField(max_length=20, choices=EventType.choices, default=EventType.STATUS_CHANGED)
    from_status = models.CharField(max_length=20, blank=True, default='')
    to_status = models.CharField(max_length=20, blank=True, default='')
    actor_user = models.ForeignKey(
        'auth.User',
        null=True,
        blank=True,
        on_delete=models.SET_NULL,
        related_name='ticket_timeline_events',
    )
    actor_ti = models.ForeignKey(
        ERPUser,
        null=True,
        blank=True,
        on_delete=models.SET_NULL,
        related_name='ticket_timeline_events',
    )
    note = models.TextField(blank=True, default='')
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self) -> str:
        return f'Timeline #{self.id} ({self.ticket_id})'


class TicketWorkLog(models.Model):
    ticket = models.ForeignKey(Ticket, on_delete=models.CASCADE, related_name='work_logs')
    attendant = models.ForeignKey(ERPUser, on_delete=models.CASCADE, related_name='ticket_work_logs')
    opened_at = models.DateTimeField()
    closed_at = models.DateTimeField()
    failure_type = models.CharField(max_length=20, choices=Ticket.FailureType.choices, default=Ticket.FailureType.NA)
    action_text = models.TextField(blank=True, default='')
    priority_label = models.CharField(max_length=60, blank=True, default='')
    exported_at = models.DateTimeField(null=True, blank=True)
    exported_path = models.CharField(max_length=500, blank=True, default='')
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self) -> str:
        return f'WorkLog #{self.id} ({self.ticket_id})'


class TicketAttendantCycle(models.Model):
    ticket = models.ForeignKey(Ticket, on_delete=models.CASCADE, related_name='attendant_cycles')
    attendant = models.ForeignKey(ERPUser, on_delete=models.CASCADE, related_name='ticket_cycles')
    current_cycle_started_at = models.DateTimeField(null=True, blank=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        unique_together = ('ticket', 'attendant')

    def __str__(self) -> str:
        return f'Cycle #{self.ticket_id}/{self.attendant_id}'


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
    group_jid = models.CharField(max_length=200, blank=True, default='')
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


class AuditLog(models.Model):
    class EventType(models.TextChoices):
        ACCESS = 'access', 'Acesso'
        ACTION = 'action', 'Acao'
        SYSTEM = 'system', 'Sistema'

    user = models.ForeignKey('auth.User', null=True, blank=True, on_delete=models.SET_NULL, related_name='audit_logs')
    username = models.CharField(max_length=150, blank=True, default='')
    full_name = models.CharField(max_length=200, blank=True, default='')
    event_type = models.CharField(max_length=20, choices=EventType.choices, default=EventType.ACCESS)
    method = models.CharField(max_length=10, blank=True, default='')
    path = models.CharField(max_length=300, blank=True, default='')
    route_name = models.CharField(max_length=120, blank=True, default='')
    status_code = models.PositiveSmallIntegerField(default=0)
    description = models.CharField(max_length=300)
    details = models.TextField(blank=True, default='')
    ip_address = models.CharField(max_length=64, blank=True, default='')
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ['-created_at', '-id']

    def __str__(self) -> str:
        return f'{self.created_at:%d/%m/%Y %H:%M} - {self.description}'
