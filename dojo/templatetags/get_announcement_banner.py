from django.utils.safestring import mark_safe
import bleach
from django import template
from dojo.models import AnnouncementBanner

register = template.Library()


@register.filter
def get_announcement_banner(attribute):
    try:
        announcement_banner = AnnouncementBanner.objects.get()

        value = getattr(announcement_banner, attribute, None)
        if value:

            if attribute == 'message':
                # Similar to login banner, only staff/admin can edit login banner, so we allow html, but still bleach it
                allowed_attributes = bleach.ALLOWED_ATTRIBUTES
                allowed_attributes['a'] = allowed_attributes['a'] + ['style', 'target']
                return mark_safe(bleach.clean(value, attributes=allowed_attributes, styles=['color', 'font-weight']))
            else:
                return value
        else:
            return False
    except Exception:
        return False
