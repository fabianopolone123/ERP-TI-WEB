from decimal import Decimal, InvalidOperation

from django import template

register = template.Library()


@register.filter
def get_item(mapping, key):
    if mapping is None or isinstance(mapping, str):
        return []
    return mapping.get(key, [])


@register.filter
def br_money(value):
    try:
        amount = Decimal(value or 0)
    except (InvalidOperation, ValueError, TypeError):
        amount = Decimal('0')
    formatted = f"{amount:,.2f}"
    return formatted.replace(",", "X").replace(".", ",").replace("X", ".")
