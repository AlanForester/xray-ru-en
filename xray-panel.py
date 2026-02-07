#!/usr/bin/env python3
from flask import Flask, render_template_string, request, redirect, jsonify
import subprocess
import json
import re
import socket
from datetime import datetime
from functools import lru_cache

app = Flask(__name__)

HTML_TEMPLATE = """
<!DOCTYPE html>
<html>
<head>
    <title>Xray Monitor</title>
    <meta charset="utf-8">
    <style>
        body { font-family: Arial; margin: 20px; background: #f5f5f5; }
        .container { max-width: 1400px; margin: 0 auto; background: white; padding: 20px; border-radius: 8px; }
        h1 { color: #333; }
        h2 { color: #666; margin-top: 30px; }
        table { width: 100%; border-collapse: collapse; margin: 20px 0; }
        th, td { padding: 10px; text-align: left; border-bottom: 1px solid #ddd; }
        th { background: #4CAF50; color: white; }
        tr:hover { background: #f5f5f5; }
        .direct { color: #4CAF50; font-weight: bold; }
        .vless { color: #2196F3; font-weight: bold; }
        .add-form { margin: 20px 0; padding: 15px; background: #f9f9f9; border-radius: 4px; }
        input[type="text"] { padding: 8px; width: 300px; margin-right: 10px; }
        button { padding: 8px 15px; background: #4CAF50; color: white; border: none; cursor: pointer; border-radius: 4px; }
        button:hover { background: #45a049; }
        .remove-btn { background: #f44336; padding: 5px 10px; font-size: 12px; }
        .remove-btn:hover { background: #da190b; }
        .status { display: inline-block; padding: 4px 8px; border-radius: 3px; font-size: 12px; }
        .status.active { background: #4CAF50; color: white; }
        .refresh { float: right; }
        .domain { color: #666; font-size: 12px; display: block; }
        .ip { font-family: monospace; }
    </style>
</head>
<body>
    <div class="container">
        <h1>🚀 Xray Monitor & Control Panel</h1>

        <h2>📊 Статус сервиса</h2>
        <p>Xray: <span class="status active">{{ xray_status }}</span></p>
        <p>Exit IP через VPS:</p>
        <ul>
            <li><strong>US_PROXY_IP</strong> (US/Miami) → .com, .io домены</li>
            <li><strong>FR_PROXY_IP</strong> (Франция) → остальные домены</li>
            <li><strong>VPS Direct</strong> → .ru домены</li>
        </ul>
        <p>Exit IP через Direct (Home): <strong>YOUR_ISP_IP</strong> → см. список ниже</p>

        <h2>🌐 Прямые маршруты (Direct)</h2>
        <table>
            <tr><th>Домен</th><th>Действие</th></tr>
            {% for domain in direct_domains %}
            <tr>
                <td>{{ domain }}</td>
                <td><button class="remove-btn" onclick="removeDomain('{{ domain }}')">Удалить</button></td>
            </tr>
            {% endfor %}
        </table>

        <div class="add-form">
            <form method="post" action="/add">
                <input type="text" name="domain" placeholder="Введите домен (например: example.com)" required>
                <button type="submit">Добавить в Direct</button>
            </form>
        </div>

        <h2>📝 Недавние соединения <button class="refresh" onclick="location.reload()">🔄 Обновить</button></h2>
        <table>
            <tr><th>Время</th><th>Клиент</th><th>Назначение</th><th>Маршрут</th></tr>
            {% for conn in connections %}
            <tr>
                <td>{{ conn.time }}</td>
                <td>{{ conn.client }}</td>
                <td>
                    <span class="ip">{{ conn.dest }}</span>
                    {% if conn.domain %}
                    <span class="domain">→ {{ conn.domain }}</span>
                    {% endif %}
                </td>
                <td class="{{ conn.route_class }}">{{ conn.route }}</td>
            </tr>
            {% endfor %}
        </table>

        <h2>🔍 DNS Запросы <button class="refresh" onclick="location.reload()">🔄 Обновить</button></h2>
        <table>
            <tr><th>Время</th><th>Клиент</th><th>Домен</th><th>Тип</th></tr>
            {% for query in dns_queries %}
            <tr>
                <td>{{ query.time }}</td>
                <td>{{ query.client }}</td>
                <td>{{ query.domain }}</td>
                <td>{{ query.type }}</td>
            </tr>
            {% endfor %}
        </table>
    </div>

    <script>
    function removeDomain(domain) {
        if (confirm('Удалить ' + domain + ' из Direct?')) {
            fetch('/remove', {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({domain: domain})
            }).then(() => location.reload());
        }
    }
    </script>
</body>
</html>
"""

def get_xray_status():
    try:
        result = subprocess.run(['systemctl', 'is-active', 'xray'], capture_output=True, text=True)
        return result.stdout.strip()
    except:
        return "unknown"

def get_direct_domains():
    try:
        with open('/etc/xray/config.json', 'r') as f:
            config = json.load(f)
        all_domains = []
        for rule in config['routing']['rules']:
            if rule.get('outboundTag') == 'direct' and 'domain' in rule:
                for d in rule['domain']:
                    if d.startswith('domain:'):
                        all_domains.append(d.replace('domain:', ''))
                    elif not d.startswith('geosite:') and not d.startswith('apt.') and not d.startswith('archive.'):
                        all_domains.append(d)
        return all_domains
    except:
        pass
    return []

@lru_cache(maxsize=1000)
def reverse_dns(ip):
    """Reverse DNS lookup with caching"""
    try:
        # Skip private IPs
        if ip.startswith('192.168.') or ip.startswith('10.') or ip.startswith('172.'):
            return None
        # Timeout after 0.2 seconds (reduced for better performance)
        socket.setdefaulttimeout(0.2)
        hostname = socket.gethostbyaddr(ip)[0]
        return hostname if hostname != ip else None
    except:
        return None

def get_recent_connections():
    """Parse xray access.log for recent connections"""
    try:
        result = subprocess.run(['tail', '-100', '/var/log/xray/access.log'],
                              capture_output=True, text=True)
        connections = []
        seen = set()  # Deduplicate
        for line in result.stdout.split('\n'):
            # Match: "2026/02/07 18:27:36.820039 from 192.168.1.132:50431 accepted tcp:5.28.195.2:443 [vless-atel]"
            match = re.search(r'(\d{2}:\d{2}:\d{2}).*from ([\d.]+):\d+ accepted \w+:([\d.a-z\-\.]+):(\d+) \[([\w-]+)\]', line)
            if match:
                time, client, dest_ip, port, route = match.groups()

                # Create unique key for deduplication
                key = f"{dest_ip}:{port}:{route}"
                if key in seen:
                    continue
                seen.add(key)

                route_class = 'direct' if route == 'direct' else 'vless'

                # Try to get domain name
                domain = None
                # Check if dest_ip looks like a domain already
                if not dest_ip.replace('.', '').isdigit():
                    domain = dest_ip
                    dest_display = f"{dest_ip}:{port}"
                else:
                    # Try reverse DNS lookup (with short timeout)
                    domain = reverse_dns(dest_ip)
                    dest_display = f"{dest_ip}:{port}"

                connections.append({
                    'time': time,
                    'client': client,
                    'dest': dest_display,
                    'domain': domain,
                    'route': route,
                    'route_class': route_class
                })
        return connections[:30]
    except:
        return []

def get_dns_queries():
    """Parse dnsmasq log for DNS queries"""
    try:
        result = subprocess.run(['tail', '-200', '/var/log/dnsmasq.log'],
                              capture_output=True, text=True)
        queries = []
        seen = set()
        for line in result.stdout.split('\n'):
            # Match: "Feb  7 18:16:00 dnsmasq[1839615]: query[A] google.com from 192.168.1.132"
            match = re.search(r'(\d{2}:\d{2}:\d{2}).*query\[(\w+)\] ([^\s]+) from ([\d.]+)', line)
            if match:
                time, qtype, domain, client = match.groups()
                key = f"{domain}:{client}"
                if key not in seen and not domain.startswith('in-addr.arpa'):
                    seen.add(key)
                    queries.append({
                        'time': time,
                        'client': client,
                        'domain': domain,
                        'type': qtype
                    })
        return queries[:50]
    except:
        return []

def add_domain_to_direct(domain):
    domain = domain.strip().replace('http://', '').replace('https://', '').split('/')[0]
    with open('/etc/xray/config.json', 'r') as f:
        config = json.load(f)

    for rule in config['routing']['rules']:
        if rule.get('outboundTag') == 'direct' and 'domain' in rule:
            domain_entry = f"domain:{domain}"
            if domain_entry not in rule['domain'] and domain not in rule['domain']:
                rule['domain'].append(domain_entry)
                break

    with open('/etc/xray/config.json', 'w') as f:
        json.dump(config, f, indent=2)

    subprocess.run(['systemctl', 'restart', 'xray'])

def remove_domain_from_direct(domain):
    with open('/etc/xray/config.json', 'r') as f:
        config = json.load(f)

    # Remove domain from ALL direct rules (not just first one)
    for rule in config['routing']['rules']:
        if rule.get('outboundTag') == 'direct' and 'domain' in rule:
            rule['domain'] = [d for d in rule['domain'] if domain not in d]

    with open('/etc/xray/config.json', 'w') as f:
        json.dump(config, f, indent=2)

    subprocess.run(['systemctl', 'restart', 'xray'])

@app.route('/')
def index():
    return render_template_string(HTML_TEMPLATE,
                                 xray_status=get_xray_status(),
                                 direct_domains=get_direct_domains(),
                                 connections=get_recent_connections(),
                                 dns_queries=get_dns_queries())

@app.route('/add', methods=['POST'])
def add():
    domain = request.form.get('domain')
    if domain:
        add_domain_to_direct(domain)
    return redirect('/')

@app.route('/remove', methods=['POST'])
def remove():
    domain = request.json.get('domain')
    if domain:
        remove_domain_from_direct(domain)
    return jsonify({'status': 'ok'})

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8080, debug=False)
