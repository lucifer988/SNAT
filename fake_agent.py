#!/usr/bin/env python3
"""Minimal local fake SNAT Agent for web UI / rule-flow verification.

Purpose:
- lets the web panel exercise add/list/delete rule flows without a real iptables host
- returns the JSON shape expected by the web backend

This is intentionally tiny and only for local QA / development.
"""

from flask import Flask, request, jsonify
import os

app = Flask(__name__)
TOKEN = os.environ.get('AGENT_TOKEN', 'token-qa')
RULES = {}


def ok_auth(req):
    """Accept signed requests or the exact Bearer token used for local QA."""
    sig = req.headers.get('X-Signature')
    auth = req.headers.get('Authorization', '')
    return bool(sig) or auth == f'Bearer {TOKEN}'


@app.route('/add_rule', methods=['POST'])
def add_rule():
    if not ok_auth(request):
        return jsonify({'error': 'Unauthorized'}), 401
    data = request.get_json(silent=True) or {}
    lp = int(data.get('local_port', 0) or 0)
    tp = int(data.get('target_port', 0) or 0)
    target_ip = str(data.get('target_ip') or '')
    target_host = str(data.get('target_host') or target_ip)
    if not (1 <= lp <= 65535 and 1 <= tp <= 65535 and target_ip):
        return jsonify({'success': False, 'error': 'invalid input'}), 400
    RULES[str(lp)] = {
        'target_ip': target_ip,
        'target_host': target_host,
        'target_port': tp,
        'traffic_limit_gb': int(data.get('traffic_limit_gb', 0) or 0),
        'traffic_bytes': 0,
        'last_counter': 0,
    }
    return jsonify({'success': True, 'resolved_ip': target_ip, 'target_host': target_host})


@app.route('/delete_rule', methods=['POST'])
def delete_rule():
    if not ok_auth(request):
        return jsonify({'error': 'Unauthorized'}), 401
    data = request.get_json(silent=True) or {}
    lp = str(int(data.get('local_port', 0) or 0))
    RULES.pop(lp, None)
    return jsonify({'success': True})


@app.route('/list_rules', methods=['GET'])
def list_rules():
    if not ok_auth(request):
        return jsonify({'error': 'Unauthorized'}), 401
    return jsonify(RULES)


@app.route('/health', methods=['GET'])
def health():
    if not request.headers.get('X-Signature') and not request.headers.get('Authorization'):
        return jsonify({'status': 'ok'})
    if not ok_auth(request):
        return jsonify({'error': 'Unauthorized'}), 401
    return jsonify({
        'status': 'ok',
        'ip_forward': True,
        'iptables_ok': True,
        'docker_ok': True,
        'rules_count': len(RULES),
        'dns_refresh_interval': 60,
    })


@app.route('/get_traffic/<int:port>', methods=['GET'])
def get_traffic(port):
    if not ok_auth(request):
        return jsonify({'error': 'Unauthorized'}), 401
    return jsonify({'success': True, 'bytes': 0, 'current_counter': 0})


@app.route('/get_connections/<int:port>', methods=['GET'])
def get_connections(port):
    if not ok_auth(request):
        return jsonify({'error': 'Unauthorized'}), 401
    return jsonify({'success': True, 'active_connections': 0})


@app.route('/check_traffic_limit', methods=['POST'])
def check_traffic_limit():
    if not ok_auth(request):
        return jsonify({'error': 'Unauthorized'}), 401
    return jsonify({'success': True, 'stopped': False})


@app.route('/healthz', methods=['GET'])
def healthz():
    return jsonify({'status': 'ok'})


if __name__ == '__main__':
    app.run(host='127.0.0.1', port=8888, debug=False)

