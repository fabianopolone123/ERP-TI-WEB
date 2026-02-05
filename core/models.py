from django.db import models


class ERPUser(models.Model):
    full_name = models.CharField(max_length=200)
    role = models.CharField(max_length=120, blank=True, default='')
    department = models.CharField(max_length=120, blank=True, default='')
    username = models.CharField(max_length=150, unique=True, null=True, blank=True)
    ad_guid = models.CharField(max_length=64, unique=True, blank=True, default='')
    is_active = models.BooleanField(default=True)

    def __str__(self) -> str:
        return self.full_name
