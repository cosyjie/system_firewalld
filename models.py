from django.db import models

from .conf import protocol_choices


class Ports(models.Model):
    protocol = models.CharField(max_length=10, default="tcp", choices=protocol_choices)
    ports = models.CharField(max_length=50)
    types = models.CharField(max_length=10)
    address = models.CharField(max_length=10, null=True, blank=True)
    description = models.TextField(null=True, blank=True)
    create_at = models.DateTimeField(auto_now_add=True)
