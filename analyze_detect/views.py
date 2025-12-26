import json
import time
from django.http import JsonResponse, HttpResponseBadRequest
from django.views.decorators.http import require_http_methods
from django.views.decorators.csrf import csrf_exempt
from django.utils import timezone
from django.shortcuts import get_object_or_404, render

from .utils import detect_xss, detect_sqli
from .models import Scan, MonitoredSite


@require_http_methods(['GET', 'POST'])
def index(request):
    """Serve index page with scan form or handle scan submission."""
    if request.method == 'POST':
        # Handle JSON POST from form
        try:
            data = json.loads(request.body.decode('utf-8'))
        except:
            data = {}

        url = data.get('url', '').strip()
        if not url:
            return JsonResponse({'error': 'Missing url parameter'}, status=400)

        deep_scan = data.get('deep_scan', False)
        follow_links = data.get('follow_links', False)
        blind_detection = data.get('blind_detection', False)

        # Create scan object and start scanning
        scan = Scan.objects.create(
            url=url,
            status='pending',
            deep_scan=deep_scan,
            follow_links=follow_links,
            blind_detection=blind_detection,
        )
        
        # Perform scan synchronously (for now)
        _perform_scan(scan)

        return JsonResponse({'scan_id': scan.id})

    # GET request: return form page
    recent_scans = Scan.objects.filter(status='completed').order_by('-created_at')[:10]
    return render(request, 'index.html', {'recent_scans': recent_scans})


def _perform_scan(scan):
    """Execute the vulnerability scan for a given Scan object."""
    scan.mark_scanning()
    start_time = time.time()

    try:
        # Detect XSS
        xss_result = detect_xss(scan.url, deep_scan=scan.deep_scan)
        scan.xss_findings = xss_result

        # Detect SQLi
        sqli_result = detect_sqli(scan.url, deep_scan=scan.deep_scan, blind_detection=scan.blind_detection)
        scan.sqli_findings = sqli_result

        # Mark as vulnerable if either test found issues
        scan.vulnerable = xss_result.get('vulnerable', False) or sqli_result.get('vulnerable', False)

        scan.duration = time.time() - start_time
        scan.mark_complete()

    except Exception as e:
        scan.mark_error(str(e))


@require_http_methods(['GET'])
def result(request, scan_id):
    """Display scan results for a given scan ID."""
    scan = get_object_or_404(Scan, pk=scan_id)
    return render(request, 'result.html', {'scan': scan})


def _get_url_from_request(request):
    """Extract URL from request (GET, POST form, or JSON body)."""
    url = request.GET.get('url') or request.POST.get('url')
    if not url:
        try:
            body = request.body.decode('utf-8')
            if body:
                data = json.loads(body)
                url = data.get('url')
        except Exception:
            pass
    return url


@csrf_exempt
@require_http_methods(['GET', 'POST'])
def detect_vulnerabilities(request):
    """API endpoint for direct vulnerability detection (legacy)."""
    url = _get_url_from_request(request)
    if not url:
        return HttpResponseBadRequest(json.dumps({'error': 'Missing "url" parameter'}), content_type='application/json')

    xss_result = detect_xss(url)
    sqli_result = detect_sqli(url)

    result = {
        'url': url,
        'detected_at': timezone.now().isoformat(),
        'xss': xss_result,
        'sqli': sqli_result,
    }
    return JsonResponse(result)


@csrf_exempt
@require_http_methods(['POST'])
def start_monitor(request):
    """Start monitoring a site (legacy API)."""
    url = _get_url_from_request(request)
    if not url:
        return HttpResponseBadRequest(json.dumps({'error': 'Missing "url" parameter'}), content_type='application/json')
    data = {}
    try:
        body = request.body.decode('utf-8')
        if body:
            data = json.loads(body)
    except Exception:
        data = {}

    interval = int(data.get('interval', 3600))  # default to 1 hour
    ms, created = MonitoredSite.objects.get_or_create(url=url, defaults={'interval': interval, 'active': True})
    if not created:
        ms.interval = interval
        ms.active = True
        ms.save()

    return JsonResponse({'status': 'monitor_started', 'id': ms.id, 'url': ms.url})


@require_http_methods(['GET'])
def list_monitored(request):
    """List all monitored sites (legacy API)."""
    items = []
    for ms in MonitoredSite.objects.all():
        items.append({
            'id': ms.id,
            'url': ms.url,
            'interval': ms.interval,
            'active': ms.active,
            'last_checked': ms.last_checked.isoformat() if ms.last_checked else None,
            'last_result': ms.last_result,
        })
    return JsonResponse({'monitored': items})


@csrf_exempt
@require_http_methods(['POST'])
def stop_monitor(request, pk):
    """Stop monitoring a site (legacy API)."""
    ms = get_object_or_404(MonitoredSite, pk=pk)
    ms.active = False
    ms.save()
    return JsonResponse({'status': 'stopped', 'id': ms.id})
