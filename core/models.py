from django.db import models


class ERPGroup(models.Model):
    name = models.CharField(max_length=120, unique=True)

    def __str__(self) -> str:
        return self.name


class ERPUser(models.Model):
    full_name = models.CharField(max_length=200)
    role = models.CharField(max_length=120, blank=True, default='')
    department = models.CharField(max_length=120, blank=True, default='')
    username = models.CharField(max_length=150, unique=True, null=True, blank=True)
    ad_guid = models.CharField(max_length=64, unique=True, blank=True, default='')
    is_active = models.BooleanField(default=True)
    group = models.ForeignKey(ERPGroup, null=True, blank=True, on_delete=models.SET_NULL)

    def __str__(self) -> str:
        return self.full_name
