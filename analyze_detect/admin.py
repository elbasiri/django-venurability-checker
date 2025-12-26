from django.contrib import admin
from .models import MonitoredSite, Scan


@admin.register(MonitoredSite)
class MonitoredSiteAdmin(admin.ModelAdmin):
    list_display = ('id', 'url', 'active', 'interval', 'last_checked')
    readonly_fields = ('created_at', 'updated_at', 'last_checked')
    search_fields = ('url',)


@admin.register(Scan)
class ScanAdmin(admin.ModelAdmin):
    list_display = ('id', 'url', 'status', 'vulnerable', 'created_at')
    readonly_fields = ('created_at', 'updated_at', 'completed_at', 'xss_findings', 'sqli_findings')
    search_fields = ('url',)
    list_filter = ('status', 'vulnerable', 'created_at')

