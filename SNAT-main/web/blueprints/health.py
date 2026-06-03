"""Health probe blueprint. Returns a minimal payload (no env/config leakage)."""
import sqlite3
from flask import Blueprint, jsonify
from web import app as _app  # 仅引用模块，避免循环 import

bp = Blueprint('health', __name__)


@bp.route('/healthz', methods=['GET'])
def healthz():
    try:
        conn = sqlite3.connect(_app.DB_FILE)
        conn.execute('SELECT 1')
        conn.close()
        return jsonify({'status': 'ok'})
    except Exception:
        return jsonify({'status': 'error'}), 500
