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
