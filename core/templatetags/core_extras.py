from django import template

register = template.Library()


@register.filter
def get_item(mapping, key):
    if mapping is None or isinstance(mapping, str):
        return []
    return mapping.get(key, [])
