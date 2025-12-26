from django.db import models
from django.utils import timezone
import json


class Scan(models.Model):
    STATUS_CHOICES = [
        ('pending', 'Pending'),
        ('scanning', 'Scanning'),
        ('completed', 'Completed'),
        ('error', 'Error'),
    ]

    url = models.URLField()
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='pending')
    vulnerable = models.BooleanField(default=False)
    
    # Scan options
    deep_scan = models.BooleanField(default=False)
    follow_links = models.BooleanField(default=False)
    blind_detection = models.BooleanField(default=False)
    
    # Results
    xss_findings = models.JSONField(default=dict)
    sqli_findings = models.JSONField(default=dict)
    
    # Metadata
    duration = models.FloatField(null=True, blank=True)
    pages_crawled = models.IntegerField(default=1)
    error_message = models.TextField(null=True, blank=True)
    
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    completed_at = models.DateTimeField(null=True, blank=True)

    def mark_complete(self):
        self.status = 'completed'
        self.completed_at = timezone.now()
        self.save()

    def mark_scanning(self):
        self.status = 'scanning'
        self.save()

    def mark_error(self, msg):
        self.status = 'error'
        self.error_message = msg
        self.completed_at = timezone.now()
        self.save()

    def __str__(self):
        return f"Scan #{self.id}: {self.url} ({self.status})"


class MonitoredSite(models.Model):
    url = models.URLField(unique=True)
    interval = models.IntegerField(default=3600, help_text='Interval in seconds between scans')
    last_checked = models.DateTimeField(null=True, blank=True)
    active = models.BooleanField(default=True)
    last_result = models.JSONField(null=True, blank=True)

    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def touch(self, result=None):
        self.last_checked = timezone.now()
        if result is not None:
            self.last_result = result
        self.save()

    def __str__(self):
        return f"MonitoredSite(id={self.id}, url={self.url})"

