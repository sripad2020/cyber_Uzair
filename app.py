from flask import Flask, render_template, request, jsonify
import requests
import whois
import datetime
import hashlib
import shodan
import dns.resolver
import ssl
import socket
from OpenSSL import SSL

app = Flask(__name__)


VT_API_KEY = '99e4922915b2a1c753dfd66e541d41df6a3522cb906b6c0d6ae7c1df6f529ae5'
SHODAN_API_KEY = '3pEzEzIv84bpdS6e3fvftB3d85RA8GZb'


@app.route('/')
def index():
    return render_template('home.html')  # Your HTML form


@app.route('/analyze', methods=['POST'])
def analyze_threats():
    results = {}

    # Phishing Detection
    if 'phishing-url' in request.form and request.form['phishing-url']:
        url = request.form['phishing-url']
        results['phishing_url'] = check_phishing_url(url)

    if 'email-content' in request.form and request.form['email-content']:
        email_content = request.form['email-content']
        results['email_analysis'] = analyze_email_content(email_content)

    if 'domain-age' in request.form and request.form['domain-age']:
        domain = request.form['domain-age']
        results['domain_age'] = check_domain_age(domain)

    # Malware Analysis
    if 'file-upload' in request.files and request.files['file-upload']:
        uploaded_file = request.files['file-upload']
        results['file_scan'] = scan_uploaded_file(uploaded_file)

    if 'file-hash' in request.form and request.form['file-hash']:
        file_hash = request.form['file-hash']
        results['hash_lookup'] = check_file_hash(file_hash)

    # Network Threat Detection
    if 'ip-check' in request.form and request.form['ip-check']:
        ip_address = request.form['ip-check']
        results['ip_reputation'] = check_ip_reputation(ip_address)

    if 'port-scan' in request.form and request.form['port-scan']:
        ip_address = request.form['port-scan']
        results['port_scan'] = scan_ports(ip_address)

    if 'dns-history' in request.form and request.form['dns-history']:
        domain = request.form['dns-history']
        results['dns_history'] = check_dns_history(domain)

    if 'ssl-check' in request.form and request.form['ssl-check']:
        url = request.form['ssl-check']
        results['ssl_check'] = check_ssl_certificate(url)

    # Credential Protection
    if 'email-check' in request.form and request.form['email-check']:
        email = request.form['email-check']
        results['email_breach'] = check_email_breach(email)

    if 'password-check' in request.form and request.form['password-check']:
        password = request.form['password-check']
        results['password_breach'] = check_password_breach(password)

    if 'darkweb-check' in request.form and request.form['darkweb-check']:
        credential = request.form['darkweb-check']
        results['darkweb_search'] = search_darkweb(credential)

    if 'phone-check' in request.form and request.form['phone-check']:
        phone = request.form['phone-check']
        results['phone_reputation'] = check_phone_reputation(phone)

    # Advanced Threat Detection
    if 'bitcoin-address' in request.form and request.form['bitcoin-address']:
        btc_address = request.form['bitcoin-address']
        results['bitcoin_reputation'] = check_bitcoin_address(btc_address)

    if 'threat-report' in request.form and request.form['threat-report']:
        indicator = request.form['threat-report']
        results['threat_intel'] = generate_threat_report(indicator)

    if 'cve-search' in request.form and request.form['cve-search']:
        software = request.form['cve-search']
        results['cve_search'] = search_cve(software)

    if 'geolocation-ip' in request.form and request.form['geolocation-ip']:
        ip_address = request.form['geolocation-ip']
        results['geolocation'] = get_ip_geolocation(ip_address)

    return jsonify(results)


# Phishing Detection Functions
def check_phishing_url(url):
    try:
        # Google Safe Browsing API (simplified)
        params = {
            'client': 'cybermind',
            'apikey': 'AIzaSyDyroTCmCRaundFKZL4z6rBoEnKCSIa9Qk',
            'appver': '1.0',
            'pver': '3.1',
            'url': url
        }
        response = requests.post('https://safebrowsing.googleapis.com/v4/threatMatches:find', params=params)
        return response.json()
    except Exception as e:
        return {'error': str(e)}


def analyze_email_content(content):
    """Analyze email content for phishing patterns"""
    # This is a simplified version - in reality you'd use SpamAssassin or similar
    phishing_keywords = ['urgent', 'password', 'verify', 'account', 'suspended', 'immediately']
    score = 0
    matches = []

    content_lower = content.lower()
    for keyword in phishing_keywords:
        if keyword in content_lower:
            score += 1
            matches.append(keyword)

    return {
        'phishing_score': score,
        'matched_keywords': matches,
        'is_suspicious': score > 2
    }


def check_domain_age(domain):
    """Check when a domain was registered"""
    try:
        domain_info = whois.whois(domain)
        creation_date = domain_info.creation_date
        if isinstance(creation_date, list):
            creation_date = creation_date[0]

        age = (datetime.datetime.now() - creation_date).days if creation_date else None
        return {
            'domain': domain,
            'creation_date': str(creation_date),
            'age_days': age,
            'is_new': age is not None and age < 30  # Considered new if < 30 days
        }
    except Exception as e:
        return {'error': str(e)}


# Malware Analysis Functions
def scan_uploaded_file(file):
    """Scan uploaded file with VirusTotal"""
    try:
        vt = VirusTotalPublicApi(VT_API_KEY)
        file_hash = hashlib.sha256(file.read()).hexdigest()
        file.seek(0)  # Reset file pointer

        # First check by hash
        response = vt.get_file_report(file_hash)
        if response['response_code'] == 200:
            return response

        # If not found, upload the file
        files = {'file': (file.filename, file)}
        response = requests.post('https://www.virustotal.com/vtapi/v2/file/scan',
                                 files=files,
                                 params={'apikey': VT_API_KEY})
        return response.json()
    except Exception as e:
        return {'error': str(e)}


def check_file_hash(file_hash):
    """Check file hash against VirusTotal"""
    try:
        vt = VirusTotalPublicApi(VT_API_KEY)
        response = vt.get_file_report(file_hash)
        return response
    except Exception as e:
        return {'error': str(e)}


# Network Threat Detection Functions
def check_ip_reputation(ip_address):
    """Check IP reputation with AbuseIPDB"""
    try:
        headers = {
            'Key': '8d727504a8cb301f17446f78bd41dfa8b2c53e029c1de79fb2f8ca9b1cd3f7e444f42f87ab7ee058',
            'Accept': 'application/json'
        }
        params = {
            'ipAddress': ip_address,
            'maxAgeInDays': '90'
        }
        response = requests.get('https://api.abuseipdb.com/api/v2/check',
                                headers=headers,
                                params=params)
        return response.json()
    except Exception as e:
        return {'error': str(e)}


def scan_ports(ip_address):
    """Scan for open ports using Shodan"""
    try:
        api = shodan.Shodan(SHODAN_API_KEY)
        host = api.host(ip_address)
        return {
            'ip': host['ip_str'],
            'ports': host.get('ports', []),
            'vulnerabilities': host.get('vulns', []),
            'services': [{'port': item['port'], 'data': item['data']} for item in host.get('data', [])]
        }
    except Exception as e:
        return {'error': str(e)}


def check_dns_history(domain):
    """Check DNS history (simplified - would use SecurityTrails in production)"""
    try:
        # This is a simplified version - would use SecurityTrails API in production
        answers = dns.resolver.resolve(domain, 'A')
        return {
            'domain': domain,
            'ip_addresses': [str(rdata) for rdata in answers]
        }
    except Exception as e:
        return {'error': str(e)}


def check_ssl_certificate(url):
    """Check SSL/TLS certificate"""
    try:
        hostname = url.replace('https://', '').replace('http://', '').split('/')[0]
        context = ssl.create_default_context()

        with socket.create_connection((hostname, 443)) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()

        # Get more details with OpenSSL
        cert = SSL.Connection(SSL.SSLv23_METHOD, socket.socket(socket.AF_INET, socket.SOCK_STREAM))
        cert.connect((hostname, 443))
        cert.do_handshake()
        x509 = cert.get_peer_certificate()

        return {
            'subject': dict(x[0] for x in cert['subject']),
            'issuer': dict(x[0] for x in cert['issuer']),
            'version': cert['version'],
            'serialNumber': cert['serialNumber'],
            'notBefore': cert['notBefore'],
            'notAfter': cert['notAfter'],
            'expires_in_days': (datetime.datetime.strptime(cert['notAfter'],
                                                           '%b %d %H:%M:%S %Y %Z') - datetime.datetime.now()).days,
            'extensions': cert.get('extensions', []),
            'openssl_details': {
                'signature_algorithm': x509.get_signature_algorithm().decode('utf-8'),
                'bits': x509.get_pubkey().bits()
            }
        }
    except Exception as e:
        return {'error': str(e)}


# Credential Protection Functions
def check_email_breach(email):
    """Check if email appears in breaches using HIBP"""
    try:
        headers = {
            'hibp-api-key': HIBP_API_KEY,
            'user-agent': 'CyberMind-Threat-Detection'
        }
        response = requests.get(f'https://haveibeenpwned.com/api/v3/breachedaccount/{email}',
                                headers=headers)
        if response.status_code == 404:
            return {'breaches': []}
        return response.json()
    except Exception as e:
        return {'error': str(e)}


def check_password_breach(password):
    """Check if password has been exposed (using k-anonymity)"""
    try:
        # Hash the password with SHA-1
        sha1_password = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
        prefix = sha1_password[:5]

        # Check against HIBP
        response = requests.get(f'https://api.pwnedpasswords.com/range/{prefix}')
        if response.status_code == 200:
            hashes = response.text.splitlines()
            for h in hashes:
                if sha1_password[5:] in h:
                    count = int(h.split(':')[1])
                    return {
                        'is_compromised': True,
                        'times_exposed': count
                    }
            return {'is_compromised': False}
        return {'error': 'API request failed'}
    except Exception as e:
        return {'error': str(e)}


def search_darkweb(credential):
    """Search for credentials on the dark web (simulated)"""
    # Note: In a real implementation, you would use DeHashed API or similar
    return {'warning': 'This is a simulated response. Real implementation would use DeHashed API.'}


def check_phone_reputation(phone):
    """Check phone number reputation using NumValidate API"""
    try:
        response = requests.get(
            f'https://api.numvalidate.com/validate',
            params={
                'number': phone,
                'apikey': '033bf1b653870d343b14447635325f1d',
                'country_code': ''  # Optional
            }
        )

        if response.status_code == 200:
            data = response.json()
            return {
                'valid': data.get('valid'),
                'carrier': data.get('carrier'),
                'line_type': data.get('line_type'),
                'is_disposable': data.get('disposable', False),
                'is_possible': data.get('possible'),
                'country': data.get('country_name')
            }
        else:
            return {'error': f"API request failed with status {response.status_code}"}
    except Exception as e:
        return {'error': str(e)}

# Advanced Threat Detection Functions
def generate_threat_report(indicator):
    """Generate threat intelligence report using ThreatMiner API"""
    try:
        # First determine if the indicator is IP, domain, or hash
        indicator_type = None
        if '.' in indicator and len(indicator.split('.')) >= 2:
            indicator_type = 'domain'
        elif indicator.count(':') >= 2:  # IPv6
            indicator_type = 'ip'
        elif indicator.replace('.', '').isdigit():  # IPv4
            indicator_type = 'ip'
        elif len(indicator) in [32, 40, 64]:  # MD5, SHA-1, SHA-256
            indicator_type = 'hash'

        if not indicator_type:
            return {'error': 'Could not determine indicator type'}

        base_url = 'https://api.threatminer.org/v2'
        endpoints = {
            'ip': f'{base_url}/host.php?q={indicator}&rt=1',
            'domain': f'{base_url}/domain.php?q={indicator}&rt=1',
            'hash': f'{base_url}/sample.php?q={indicator}&rt=1'
        }

        response = requests.get(endpoints[indicator_type])

        if response.status_code == 200:
            data = response.json()

            # Process the data into a structured report
            report = {
                'indicator': indicator,
                'type': indicator_type,
                'sources': [],
                'related_indicators': [],
                'malware_families': [],
                'tags': []
            }

            # Parse different response types
            if indicator_type == 'ip':
                if data.get('results'):
                    for result in data['results']:
                        if result.get('asn'):
                            report['asn'] = result['asn']
                        if result.get('country'):
                            report['country'] = result['country']
                        if result.get('malware'):
                            report['malware_families'].extend(result['malware'])
                        if result.get('sources'):
                            report['sources'].extend(result['sources'])

            elif indicator_type == 'domain':
                if data.get('results'):
                    for result in data['results']:
                        if result.get('ip'):
                            report['related_indicators'].append({
                                'type': 'ip',
                                'value': result['ip']
                            })
                        if result.get('malware'):
                            report['malware_families'].extend(result['malware'])

            elif indicator_type == 'hash':
                if data.get('results'):
                    for result in data['results']:
                        if result.get('md5'):
                            report['hash_md5'] = result['md5']
                        if result.get('sha1'):
                            report['hash_sha1'] = result['sha1']
                        if result.get('sha256'):
                            report['hash_sha256'] = result['sha256']
                        if result.get('av_detections'):
                            report['av_detections'] = result['av_detections']
                        if result.get('tags'):
                            report['tags'].extend(result['tags'])

            return report
        else:
            return {'error': f"API request failed with status {response.status_code}"}
    except Exception as e:
        return {'error': str(e)}
def search_cve(software):
    try:
        response = requests.get(f'https://cve.circl.lu/api/search/{software}')
        return response.json()
    except Exception as e:
        return {'error': str(e)}


def get_ip_geolocation(ip_address):
    try:
        response = requests.get(f'http://ip-api.com/json/{ip_address}')
        data = response.json()
        if data.get('isp', '').lower() in ['vpn', 'proxy'] or data.get('org', '').lower() in ['vpn', 'proxy']:
            data['is_proxy'] = True
        else:
            data['is_proxy'] = False
        return data
    except Exception as e:
        return {'error': str(e)}


if __name__ == '__main__':
    app.run(debug=True)