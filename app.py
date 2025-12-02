from flask import Flask, render_template, request, jsonify
from urllib.parse import urlparse
import requests
import whois
from datetime import datetime
import tldextract
import socket
import re

app = Flask(__name__)

def analyze_url_pattern(url):
    score = 0
    details = {
        'suspicious_keywords': [],
        'url_length': len(url),
        'has_at_symbol': False,
        'has_hyphens': False,
        'multiple_subdomains': False,
        'comment': 'No suspicious patterns detected'
    }
    
    # Check for suspicious keywords
    suspicious_keywords = ["login", "verify", "bank", "secure", "update", "free", "password", "confirm"]
    for keyword in suspicious_keywords:
        if keyword in url.lower():
            score += 1
            details['suspicious_keywords'].append(keyword)
    
    # Check URL length
    if len(url) > 75:
        score += 1
        details['comment'] = 'Long URL detected'
    
    # Check for @ symbol
    if '@' in url:
        score += 2
        details['has_at_symbol'] = True
        details['comment'] = 'URL contains @ symbol (suspicious)'
    
    # Check for multiple hyphens
    if url.count('-') > 3:
        score += 1
        details['has_hyphens'] = True
        details['comment'] = 'Multiple hyphens in domain (suspicious)'
    
    # Check for multiple subdomains
    domain = tldextract.extract(url).domain
    if url.count('.') > 3 and domain in url:
        score += 1
        details['multiple_subdomains'] = True
        details['comment'] = 'Multiple subdomains detected'
    
    details['score'] = score
    return details

def check_domain_age(url):
    try:
        domain = tldextract.extract(url).registered_domain
        if not domain:
            return {
                'score': 1,
                'age_days': 0,
                'whois_status': 'error',
                'comment': 'Could not extract domain'
            }
            
        domain_info = whois.whois(domain)
        creation_date = domain_info.creation_date
        
        if isinstance(creation_date, list):
            creation_date = min(creation_date)
            
        if not creation_date:
            return {
                'score': 1,
                'age_days': 0,
                'whois_status': 'no_creation_date',
                'comment': 'No creation date in WHOIS'
            }
            
        age_days = (datetime.now() - creation_date).days
        
        if age_days < 0:
            return {
                'score': 2,
                'age_days': 0,
                'whois_status': 'future_date',
                'comment': 'Domain has future creation date (suspicious)'
            }
            
        if age_days < 30:
            return {
                'score': 2,
                'age_days': age_days,
                'whois_status': 'new',
                'comment': f'New domain ({age_days} days old)'
            }
        elif age_days < 180:
            return {
                'score': 1,
                'age_days': age_days,
                'whois_status': 'relatively_new',
                'comment': f'Relatively new domain ({age_days} days)'
            }
        else:
            return {
                'score': 0,
                'age_days': age_days,
                'whois_status': 'established',
                'comment': f'Established domain ({age_days} days old)'
            }
            
    except Exception as e:
        return {
            'score': 1,
            'age_days': 0,
            'whois_status': 'error',
            'comment': f'Error checking domain age: {str(e)}'
        }

def check_ssl(url):
    try:
        if not url.startswith(('http://', 'https://')):
            url = 'https://' + url
            
        if url.startswith('http://'):
            return {
                'score': 1,
                'uses_https': False,
                'reachable': False,
                'comment': 'Uses HTTP (not secure)'
            }
            
        try:
            response = requests.get(url, timeout=5, verify=True)
            return {
                'score': 0,
                'uses_https': True,
                'reachable': True,
                'status_code': response.status_code,
                'comment': 'Uses HTTPS (secure)'
            }
        except requests.exceptions.SSLError:
            return {
                'score': 1,
                'uses_https': False,
                'reachable': True,
                'comment': 'SSL certificate error (suspicious)'
            }
        except requests.exceptions.RequestException:
            return {
                'score': 1,
                'uses_https': url.startswith('https'),
                'reachable': False,
                'comment': 'Could not establish secure connection'
            }
            
    except Exception as e:
        return {
            'score': 1,
            'uses_https': False,
            'reachable': False,
            'comment': f'Error checking SSL: {str(e)}'
        }

def check_reachability(url):
    try:
        if not url.startswith(('http://', 'https://')):
            url = 'https://' + url
            
        response = requests.get(url, timeout=5, allow_redirects=True)
        
        if response.status_code >= 400:
            return {
                'score': 1,
                'reachable': True,
                'status_code': response.status_code,
                'comment': f'Website returned error {response.status_code}'
            }
            
        return {
            'score': 0,
            'reachable': True,
            'status_code': response.status_code,
            'comment': 'Website is reachable'
        }
        
    except requests.exceptions.Timeout:
        return {
            'score': 2,
            'reachable': False,
            'comment': 'Connection timed out (suspicious)'
        }
    except requests.exceptions.RequestException as e:
        return {
            'score': 2,
            'reachable': False,
            'comment': f'Could not reach website: {str(e)}'
        }

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/scan', methods=['POST'])
def scan_url():
    data = request.get_json()
    url = data.get('url', '').strip()
    
    if not url:
        return jsonify({'error': 'URL is required'}), 400
    
    try:
        # Run all checks
        url_analysis = analyze_url_pattern(url)
        domain_age = check_domain_age(url)
        ssl_check = check_ssl(url)
        reachability = check_reachability(url)
        
        # Calculate total risk score
        total_score = (
            url_analysis.get('score', 0) +
            domain_age.get('score', 0) +
            ssl_check.get('score', 0) +
            reachability.get('score', 0)
        )
        
        # Determine status
        if total_score >= 4:
            status = 'Phishing Website'
            risk_level = 'high'
        elif total_score >= 2:
            status = 'Suspicious Website'
            risk_level = 'medium'
        else:
            status = 'Safe Website'
            risk_level = 'low'
        
        # Prepare response
        response = {
            'url': url,
            'status': status,
            'risk_level': risk_level,
            'risk_score': total_score,
            'factors': {
                'url_analysis': url_analysis,
                'domain_age': domain_age,
                'ssl': ssl_check,
                'reachability': reachability
            }
        }
        
        return jsonify(response)
        
    except Exception as e:
        return jsonify({
            'error': f'Error processing URL: {str(e)}',
            'status': 'error'
        }), 500

if __name__ == '__main__':
    app.run(debug=True)
