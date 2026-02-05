from django.db import models


class ERPGroup(models.Model):
    name = models.CharField(max_length=120, unique=True)

    def __str__(self) -> str:
        return self.name


class ERPUser(models.Model):
    full_name = models.CharField(max_length=200)
    role = models.CharField(max_length=120)
    department = models.CharField(max_length=120)
    group = models.ForeignKey(ERPGroup, null=True, blank=True, on_delete=models.SET_NULL)

    def __str__(self) -> str:
        return self.full_name
