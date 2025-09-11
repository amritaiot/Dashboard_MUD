from django.db import models

# Create your models here.
class IoTDevice(models.Model):
    name = models.CharField(max_length=100)
    mac_address = models.CharField(max_length=17)
    ip_address = models.GenericIPAddressField()
    state = models.CharField(max_length=50, default='OFF')   # Can be 'ON' or 'OFF'
    pid = models.IntegerField(null=True, blank=True)  # PID of the running script
    last_seen = models.DateTimeField(auto_now=True)
    mud_compliant = models.BooleanField(default=False)  # True if device is MUD-compliant
    mud_url = models.URLField(blank=True, null=True)
    def __str__(self):
        return f"{self.name} ({self.ip_address})"