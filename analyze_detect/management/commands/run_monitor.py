from django.core.management.base import BaseCommand
from analyze_detect.models import MonitoredSite
from analyze_detect.utils import detect_xss, detect_sqli
from django.utils import timezone
import json

class Command(BaseCommand):
    help = 'Run monitoring for active MonitoredSite entries'

    def handle(self, *args, **options):
        now = timezone.now()
        for ms in MonitoredSite.objects.filter(active=True):
            should_run = False
            if not ms.last_checked:
                should_run = True
            else:
                diff = (now - ms.last_checked).total_seconds()
                if diff >= ms.interval:
                    should_run = True

            if not should_run:
                self.stdout.write(f"Skipping {ms.url}, last checked {ms.last_checked}")
                continue

            self.stdout.write(f"Scanning {ms.url} ...")
            xss = detect_xss(ms.url)
            sqli = detect_sqli(ms.url)
            result = {'xss': xss, 'sqli': sqli, 'checked_at': now.isoformat()}
            ms.touch(result)
            self.stdout.write(json.dumps(result, indent=2))
