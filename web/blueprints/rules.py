"""Rule CRUD, toggle, bulk operations, and reconcile."""
import sqlite3
import requests
from flask import Blueprint, request, jsonify

from web import app as _app

bp = Blueprint('rules', __name__)


@bp.route('/api/rules', methods=['GET', 'POST'])
@_app.login_required
def rules():
    conn = sqlite3.connect(_app.DB_FILE, timeout=10)
    conn.row_factory = sqlite3.Row
    c = conn.cursor()

    if request.method == 'GET':
        c.execute('''SELECT r.*, s.name as server_name, s.host as server_host
                    FROM rules r JOIN servers s ON r.server_id = s.id
                    ORDER BY r.id DESC''')
        rows = [dict(row) for row in c.fetchall()]
        conn.close()
        return jsonify(rows)

    if not _app._recent_auth_ok():
        conn.close()
        return jsonify({'success': False, 'error': '网络变更需要重新验证密码', 'reauth_required': True}), 403

    data = request.json or {}
    required = ('server_id', 'local_port', 'target_ip', 'target_port')
    missing = [k for k in required if data.get(k) in (None, '')]
    if missing:
        conn.close()
        return jsonify({'success': False, 'error': f'缺少必填字段: {", ".join(missing)}'}), 400
    server_id = data['server_id']
    # 端口/目标合法性提前校验（Agent 端会再校验一次），避免脏数据落库
    try:
        lp = int(data['local_port'])
        tp = int(data['target_port'])
    except (TypeError, ValueError):
        conn.close()
        return jsonify({'success': False, 'error': '端口必须为整数'}), 400
    if not (1 <= lp <= 65535) or not (1 <= tp <= 65535):
        conn.close()
        return jsonify({'success': False, 'error': '端口范围必须在 1-65535'}), 400
    data['local_port'] = lp
    data['target_port'] = tp
    traffic_limit = data.get('traffic_limit_gb', 0)
    if 'target_host' not in data:
        data['target_host'] = ''

    c.execute('SELECT * FROM servers WHERE id = ?', (server_id,))
    server_row = c.fetchone()
    if not server_row:
        conn.close()
        return jsonify({'success': False, 'error': '服务器不存在'}), 404
    server = dict(server_row)

    c.execute('SELECT id FROM rules WHERE server_id = ? AND local_port = ?',
              (server_id, data['local_port']))
    if c.fetchone():
        conn.close()
        return jsonify({'success': False, 'error': '该服务器端口已存在规则'}), 400

    c.execute('''INSERT INTO rules (server_id, local_port, target_host, target_ip, target_port, remark, traffic_limit_gb)
                VALUES (?, ?, ?, ?, ?, ?, ?)''',
              (server_id, data['local_port'], data.get('target_host', ''), data['target_ip'], data['target_port'],
               data.get('remark', ''), traffic_limit))
    conn.commit()
    rule_id = c.lastrowid
    conn.close()

    _app.log_event('INFO', f"新增规则 {rule_id}: {data['local_port']} -> {data['target_ip']}:{data['target_port']}")

    try:
        resp = _app.agent_post(
            f"http://{server['host']}:{server['port']}/add_rule",
            _app.decrypt_token(server['token']),
            {
                'local_port': data['local_port'],
                'target_ip': data['target_ip'],
                'target_host': data.get('target_host', '') or data['target_ip'],
                'target_port': data['target_port'],
                'traffic_limit_gb': int(traffic_limit or 0)
            },
            timeout=5
        )
        payload = resp.json() or {}
        if resp.status_code != 200 or payload.get('success') is not True:
            _rollback_rule(rule_id)
            _app.log_event('ERROR', f"规则 {rule_id} 下发失败: HTTP {resp.status_code}，已回滚数据库")
            return jsonify({'success': False, 'error': f'Agent 下发失败 HTTP {resp.status_code}'}), 502

        if payload.get('resolved_ip') or payload.get('target_host'):
            conn = sqlite3.connect(_app.DB_FILE, timeout=10)
            c = conn.cursor()
            c.execute('UPDATE rules SET target_host = ?, target_ip = ? WHERE id = ?',
                      (payload.get('target_host', ''), payload.get('resolved_ip', data['target_ip']), rule_id))
            conn.commit()
            conn.close()
        _app.log_event('INFO', f"规则 {rule_id} 已下发到 Agent")

        sync_results = _app.sync_server_rules(server['id'], log_prefix=f'[添加] 服务器 {server["id"]}')
        failed = [item for item in sync_results if item.get('status') not in _app.SYNC_OK_STATUSES]
        if failed:
            _rollback_rule(rule_id)
            _app.sync_server_rules(server['id'], log_prefix=f'[添加回滚] 服务器 {server["id"]}')
            _app.log_event('ERROR', f"规则 {rule_id} 同步失败，已回滚数据库: {failed}")
            return jsonify({'success': False, 'error': 'Agent 全量同步失败', 'details': failed}), 502

        return jsonify({'success': True, 'id': rule_id})
    except Exception as e:
        _rollback_rule(rule_id)
        _app.log_event('ERROR', f"规则 {rule_id} 下发异常: {e}，已回滚数据库")
        return jsonify({'success': False, 'error': str(e)}), 502


def _rollback_rule(rule_id):
    conn = sqlite3.connect(_app.DB_FILE, timeout=10)
    c = conn.cursor()
    c.execute('DELETE FROM rules WHERE id = ?', (rule_id,))
    conn.commit()
    conn.close()


@bp.route('/api/rules/<int:rule_id>', methods=['PUT', 'DELETE'])
@_app.login_required
@_app.require_recent_auth()
def update_or_delete_rule(rule_id):
    conn = sqlite3.connect(_app.DB_FILE, timeout=10)
    conn.row_factory = sqlite3.Row
    c = conn.cursor()

    if request.method == 'PUT':
        data = request.json or {}
        if 'target_host' not in data:
            data['target_host'] = ''
        # 必填字段与端口范围前置校验，避免后续按键取值时 KeyError → 500
        for k in ('local_port', 'target_ip', 'target_port'):
            if data.get(k) in (None, ''):
                conn.close()
                return jsonify({'success': False, 'error': f'缺少必填字段: {k}'}), 400
        try:
            data['local_port'] = int(data['local_port'])
            data['target_port'] = int(data['target_port'])
        except (TypeError, ValueError):
            conn.close()
            return jsonify({'success': False, 'error': '端口必须为整数'}), 400
        if not (1 <= data['local_port'] <= 65535) or not (1 <= data['target_port'] <= 65535):
            conn.close()
            return jsonify({'success': False, 'error': '端口范围必须在 1-65535'}), 400
        c.execute('''SELECT r.*, s.host, s.port, s.token
                    FROM rules r JOIN servers s ON r.server_id = s.id
                    WHERE r.id = ?''', (rule_id,))
        row = c.fetchone()
        if not row:
            conn.close()
            return jsonify({'success': False, 'error': '规则不存在'}), 404

        rule = dict(row)
        port_changed = data['local_port'] != rule['local_port']
        ip_changed = data['target_ip'] != rule['target_ip']
        target_port_changed = data['target_port'] != rule['target_port']
        old_host_norm = (rule.get('target_host') or rule['target_ip'] or '').strip()
        new_host_norm = (data.get('target_host') or data['target_ip'] or '').strip()
        host_changed = new_host_norm != old_host_norm

        if port_changed:
            c.execute('SELECT id FROM rules WHERE server_id = ? AND local_port = ? AND id != ?',
                      (rule['server_id'], data['local_port'], rule_id))
            if c.fetchone():
                conn.close()
                return jsonify({'success': False, 'error': '该服务器端口已存在规则'}), 400

        if port_changed or ip_changed or target_port_changed or host_changed:
            token = _app.decrypt_token(rule['token']); base=f"http://{rule['host']}:{rule['port']}"
            try:
                deleted=_app.agent_post(base+'/delete_rule',token,{'local_port':rule['local_port']},timeout=5)
                if deleted.status_code!=200 or (deleted.json() or {}).get('success') is not True:
                    conn.close(); return jsonify({'success':False,'error':'删除旧规则未确认成功，编辑已中止'}),500
            except Exception as exc:
                conn.close(); return jsonify({'success':False,'error':f'删除旧规则失败，编辑已中止: {exc}'}),500
            def rollback_old():
                try:
                    rb=_app.agent_post(base+'/add_rule',token,{'local_port':rule['local_port'],'target_ip':rule['target_ip'],'target_host':rule.get('target_host') or rule['target_ip'],'target_port':rule['target_port'],'traffic_limit_gb':int(rule.get('traffic_limit_gb',0) or 0)},timeout=5)
                    return rb.status_code==200 and (rb.json() or {}).get('success') is True
                except Exception: return False
            try:
                resp=_app.agent_post(base+'/add_rule',token,{'local_port':data['local_port'],'target_ip':data['target_ip'],'target_host':data.get('target_host') or data['target_ip'],'target_port':data['target_port'],'traffic_limit_gb':int(data.get('traffic_limit_gb',0) or 0)},timeout=5)
                ok=resp.status_code==200 and (resp.json() or {}).get('success') is True
            except Exception as exc:
                ok=False; resp=None
            if not ok:
                rolled=rollback_old()
                if not rolled: c.execute("UPDATE rules SET status='desynced' WHERE id=?",(rule_id,)); conn.commit()
                conn.close(); return jsonify({'success':False,'error':f'Agent 更新失败（旧规则{"已恢复" if rolled else "恢复失败"}）'}),500
            payload=resp.json() or {}
            data['target_ip']=payload.get('resolved_ip',data['target_ip']); data['target_host']=payload.get('target_host',data.get('target_host',''))

        c.execute('''UPDATE rules SET local_port=?, target_host=?, target_ip=?, target_port=?, remark=?, traffic_limit_gb=?
                    WHERE id=?''',
                  (data['local_port'], data.get('target_host', ''), data['target_ip'], data['target_port'],
                   data.get('remark', ''), data.get('traffic_limit_gb', 0), rule_id))
        conn.commit()
        conn.close()
        _app.log_event('INFO', f"更新规则 {rule_id}: {data['local_port']} -> {data['target_ip']}:{data['target_port']}")
        _app.sync_server_rules(rule['server_id'], log_prefix=f'[编辑] 服务器 {rule["server_id"]}')
        return jsonify({'success': True})

    # DELETE
    c.execute('''SELECT r.*, s.host, s.port, s.token
                FROM rules r JOIN servers s ON r.server_id = s.id
                WHERE r.id = ?''', (rule_id,))
    row = c.fetchone()
    if not row:
        conn.close()
        return jsonify({'success': False, 'error': '规则不存在'}), 404

    rule = dict(row)
    try:
        resp = _app.agent_post(
            f"http://{rule['host']}:{rule['port']}/delete_rule",
            _app.decrypt_token(rule['token']),
            {'local_port': rule['local_port']},
            timeout=5
        )
        try:
            confirmed = resp.status_code == 200 and (resp.json() or {}).get('success') is True
        except ValueError:
            confirmed = False
        if not confirmed:
            conn.close()
            return jsonify({'success': False, 'error': f'Agent 删除失败 HTTP {resp.status_code}'}), 502
    except Exception as e:
        conn.close()
        return jsonify({'success': False, 'error': f'无法连接 Agent: {str(e)}'}), 502

    c.execute('DELETE FROM rules WHERE id = ?', (rule_id,))
    conn.commit()
    conn.close()
    _app.log_event('INFO', f"删除规则 {rule_id}: {rule['local_port']} -> {rule['target_ip']}:{rule['target_port']}")

    sync_results = _app.sync_server_rules(rule['server_id'], log_prefix=f'[删除] 服务器 {rule["server_id"]}')
    failed = [item for item in sync_results if item.get('status') not in _app.SYNC_OK_STATUSES]
    if failed:
        return jsonify({'success': False, 'error': '删除后全量同步失败', 'details': failed}), 502
    return jsonify({'success': True})


@bp.route('/api/rules/<int:rule_id>/toggle', methods=['POST'])
@_app.login_required
@_app.require_recent_auth()
def toggle_rule(rule_id):
    conn = sqlite3.connect(_app.DB_FILE, timeout=10)
    conn.row_factory = sqlite3.Row
    c = conn.cursor()

    c.execute('''SELECT r.*, s.host, s.port, s.token
                FROM rules r JOIN servers s ON r.server_id = s.id
                WHERE r.id = ?''', (rule_id,))
    row = c.fetchone()
    if not row:
        conn.close()
        return jsonify({'success': False, 'error': '规则不存在'}), 404

    rule = dict(row)
    new_enabled = 0 if rule['enabled'] else 1
    _app.log_event('INFO', f"切换规则 {rule_id}: {rule['enabled']} -> {new_enabled}")

    try:
        action = 'add_rule' if new_enabled else 'delete_rule'
        if action == 'add_rule':
            payload = {
                'local_port': rule['local_port'],
                'target_ip': rule['target_ip'],
                'target_host': rule.get('target_host', '') or rule['target_ip'],
                'target_port': rule['target_port'],
                'traffic_limit_gb': int(rule.get('traffic_limit_gb', 0) or 0),
            }
        else:
            payload = {'local_port': rule['local_port']}
        resp = _app.agent_post(
            f"http://{rule['host']}:{rule['port']}/{action}",
            _app.decrypt_token(rule['token']),
            payload,
            timeout=5
        )
        try:
            confirmed = resp.status_code == 200 and (resp.json() or {}).get('success') is True
        except ValueError:
            confirmed = False
        if not confirmed:
            conn.close()
            return jsonify({'success': False, 'error': 'Agent 操作失败'}), 500
    except Exception as e:
        _app.log_event('ERROR', f"Agent 连接失败: {e}")
        conn.close()
        return jsonify({'success': False, 'error': f'无法连接 Agent: {str(e)}'}), 500

    c.execute('UPDATE rules SET enabled = ? WHERE id = ?', (new_enabled, rule_id))
    conn.commit()
    conn.close()

    _app.log_event('INFO', f"规则 {rule_id} 状态已更新为 {new_enabled}")
    _app.sync_server_rules(rule['server_id'], log_prefix=f'[切换] 服务器 {rule["server_id"]}')
    return jsonify({'success': True, 'enabled': new_enabled})


@bp.route('/api/rules/bulk', methods=['POST'])
@_app.login_required
@_app.require_recent_auth()
def bulk_rules():
    data = request.json or {}
    action = data.get('action')
    rule_ids = data.get('rule_ids', [])
    if not isinstance(rule_ids, list) or not rule_ids:
        return jsonify({'success': False, 'error': 'rule_ids 不能为空'}), 400

    conn = sqlite3.connect(_app.DB_FILE, timeout=10)
    conn.row_factory = sqlite3.Row
    c = conn.cursor()
    placeholders = ','.join('?' * len(rule_ids))
    c.execute(
        f'SELECT r.*, s.host, s.port, s.token FROM rules r JOIN servers s ON r.server_id=s.id WHERE r.id IN ({placeholders})',
        rule_ids
    )
    rows = [dict(row) for row in c.fetchall()]
    affected, failed = [], []
    def confirmed(resp):
        try: payload=resp.json() or {}
        except Exception: payload={}
        return resp.status_code==200 and payload.get('success') is True
    for rule in rows:
        try:
            token=_app.decrypt_token(rule['token'])
            if action=='enable':
                resp=_app.agent_post(f"http://{rule['host']}:{rule['port']}/add_rule",token,{'local_port':rule['local_port'],'target_ip':rule['target_ip'],'target_host':rule.get('target_host') or rule['target_ip'],'target_port':rule['target_port'],'traffic_limit_gb':int(rule.get('traffic_limit_gb',0) or 0)},timeout=5)
                if confirmed(resp): c.execute("UPDATE rules SET enabled=1,status='active' WHERE id=?",(rule['id'],))
                else: raise RuntimeError(f'Agent 未确认启用 HTTP {resp.status_code}')
            elif action in ('disable','delete'):
                resp=_app.agent_post(f"http://{rule['host']}:{rule['port']}/delete_rule",token,{'local_port':rule['local_port']},timeout=5)
                if not confirmed(resp): raise RuntimeError(f'Agent 未确认删除 HTTP {resp.status_code}')
                if action=='disable': c.execute("UPDATE rules SET enabled=0,status='active' WHERE id=?",(rule['id'],))
                else: c.execute('DELETE FROM rules WHERE id=?',(rule['id'],))
            else:
                conn.close(); return jsonify({'success':False,'error':'不支持的 action'}),400
            affected.append(rule['id'])
        except Exception as exc:
            c.execute("UPDATE rules SET status='desynced' WHERE id=?",(rule['id'],))
            failed.append({'id':rule['id'],'error':str(exc)})
    conn.commit()
    conn.close()
    _app.log_event('INFO', f'批量规则操作 {action}: 成功 {len(affected)} 条, 失败 {len(failed)} 条')
    return jsonify({'success': True, 'affected': affected, 'failed': failed})


@bp.route('/api/rules/reconcile', methods=['POST'])
@_app.login_required
@_app.require_recent_auth()
def reconcile_rules():
    conn=sqlite3.connect(_app.DB_FILE,timeout=10); conn.row_factory=sqlite3.Row; c=conn.cursor()
    c.execute('SELECT r.*,s.host,s.port,s.token FROM rules r JOIN servers s ON r.server_id=s.id WHERE r.enabled=1 ORDER BY r.id')
    rows=[dict(x) for x in c.fetchall()]; results=[]
    for rule in rows:
        try:
            token=_app.decrypt_token(rule['token']); resp=_app.agent_get(f"http://{rule['host']}:{rule['port']}/list_rules",token,timeout=5)
            remote=(resp.json() or {}); remote=remote.get('rules',remote); entry=remote.get(str(rule['local_port']))
            limit=int(rule.get('traffic_limit_gb',0) or 0); over=limit>0 and int(rule.get('traffic_used_bytes',0) or 0)>=limit*1024**3
            if isinstance(entry,dict) and entry.get('suspended'):
                c.execute('UPDATE rules SET enabled=0 WHERE id=?',(rule['id'],)); results.append({'rule_id':rule['id'],'status':'remote_suspended'}); continue
            if entry is None:
                if over: c.execute('UPDATE rules SET enabled=0 WHERE id=?',(rule['id'],)); results.append({'rule_id':rule['id'],'status':'over_limit_skipped'}); continue
                add=_app.agent_post(f"http://{rule['host']}:{rule['port']}/add_rule",token,{'local_port':rule['local_port'],'target_ip':rule['target_ip'],'target_host':rule.get('target_host') or rule['target_ip'],'target_port':rule['target_port'],'traffic_limit_gb':limit},timeout=5)
                results.append({'rule_id':rule['id'],'status':'reapplied' if add.status_code==200 else 'failed'})
            else: results.append({'rule_id':rule['id'],'status':'ok'})
        except Exception as exc: results.append({'rule_id':rule['id'],'status':'error','error':str(exc)})
    conn.commit(); conn.close(); return jsonify({'success':True,'results':results})


@bp.route('/api/restore/reapply', methods=['POST'])
@_app.login_required
@_app.require_recent_auth()
def restore_reapply():
    conn = sqlite3.connect(_app.DB_FILE, timeout=10)
    conn.row_factory = sqlite3.Row
    c = conn.cursor()
    c.execute('SELECT r.*, s.host, s.port, s.token FROM rules r JOIN servers s ON r.server_id=s.id WHERE r.enabled = 1 ORDER BY r.id')
    rule_rows = [dict(r) for r in c.fetchall()]
    conn.close()
    results = []
    for rule in rule_rows:
        limit=int(rule.get('traffic_limit_gb',0) or 0)
        if limit>0 and int(rule.get('traffic_used_bytes',0) or 0)>=limit*1024**3:
            results.append({'rule_id':rule['id'],'status':'over_limit_skipped'}); continue
        token = _app.decrypt_token(rule['token'])
        try:
            resp = _app.agent_post(
                f"http://{rule['host']}:{rule['port']}/add_rule",
                token,
                {'local_port': rule['local_port'], 'target_ip': rule['target_ip'],
                 'target_host': rule.get('target_host', '') or rule['target_ip'],
                 'target_port': rule['target_port'], 'traffic_limit_gb': int(rule.get('traffic_limit_gb', 0) or 0)},
                timeout=5
            )
            results.append({'rule_id': rule['id'], 'status': 'ok' if resp.status_code == 200 else 'failed', 'http': resp.status_code})
        except Exception as e:
            results.append({'rule_id': rule['id'], 'status': 'error', 'error': str(e)})
    _app.audit_log('restore_reapply', 'rules', 'success', _app.json.dumps(results, ensure_ascii=False))
    return jsonify({'success': True, 'results': results})
