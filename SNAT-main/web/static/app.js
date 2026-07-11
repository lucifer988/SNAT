// SNAT Manager - 前端逻辑

// HTML 转义：所有用户可控字段（服务器名/地址、备注、target_host、后端回传的错误文本等）
// 在拼入 innerHTML 前必须经过 esc()，防止存储型/反射型 XSS。
function escapeHtml(v) {
    return String(v ?? '').replace(/[&<>"'`]/g, ch => ({
        '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;', '`': '&#96;'
    })[ch]);
}
const esc = escapeHtml;

let servers = [];
let rules = [];
let csrfToken = '';
let selectedRuleIds = new Set();
let ruleSortKey = 'created_at';
let ruleSortDir = 'desc';
let ruleFilterText = '';

// 页面加载时初始化
document.addEventListener('DOMContentLoaded', async () => {
    await getCsrfToken();
    await initTopForceHttpsToggle();
    loadServers();
    loadRules().then(() => { loadTrafficSummary(); loadConnectionsSummary(); });
    
    // 移动端检测并切换视图
    checkMobileView();
    window.addEventListener('resize', checkMobileView);
    
    // 立即检查一次流量
    checkAllTraffic();
    
    // 每1分钟检查一次流量
    setInterval(checkAllTraffic, 60 * 1000);
    setInterval(loadConnectionsSummary, 30 * 1000);
    
    // 每次加载规则后检查告警
    setInterval(() => {
        loadRules().then(() => checkTrafficAlerts());
    }, 2 * 60 * 1000); // 每2分钟检查告警
});

// 移动端视图切换
function checkMobileView() {
    const isMobile = window.innerWidth <= 768;
    const table = document.getElementById('rulesTable');
    const list = document.getElementById('rulesList');
    if (table && list) {
        table.style.display = isMobile ? 'none' : '';
        list.style.display = isMobile ? 'block' : 'none';
    }
    // 服务器表格移动端处理
    const serversTable = document.getElementById('serversTable');
    if (serversTable) {
        // 移动端用 CSS 处理，但同步切换 thead
        const thead = serversTable.querySelector('thead');
        if (thead) thead.style.display = isMobile ? 'none' : '';
    }
}

// 检查所有规则流量
async function checkAllTraffic() {
    await postWithCsrf('/api/check_all_traffic', {});
    loadRules().then(() => { loadTrafficSummary(); loadConnectionsSummary(); }); // 刷新显示
}

// 获取 CSRF Token
async function getCsrfToken() {
    const resp = await fetch('/api/csrf_token');
    const data = await resp.json();
    csrfToken = data.token;
}

// 通用 POST 请求（自动添加 CSRF Token）
async function postWithCsrf(url, data) {
    return fetch(url, {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
            'X-CSRF-Token': csrfToken
        },
        body: JSON.stringify(data)
    });
}

// 通用 DELETE 请求
async function deleteWithCsrf(url) {
    return fetch(url, {
        method: 'DELETE',
        headers: {'X-CSRF-Token': csrfToken}
    });
}

// 加载服务器列表
async function loadServers() {
    const resp = await fetch('/api/servers');
    servers = await resp.json();
    renderServers();
}

// 渲染服务器表格
function renderServers() {
    const tbody = document.querySelector('#serversTable tbody');
    tbody.innerHTML = servers.map(s => {
        const label = s.status === 'token_invalid' ? 'token异常' : s.status;
        return `
        <tr>
            <td data-label="名称">${esc(s.name)}</td>
            <td data-label="地址">${esc(s.host)}</td>
            <td data-label="端口">${s.port}</td>
            <td data-label="状态" class="status-${esc(s.status)}">${esc(label)}</td>
            <td data-label="操作" class="col-actions">
                <div class="action-group" style="justify-content:center">
                    <button class="btn-success" data-act="editServer" data-arg="${s.id}">编辑</button>
                    <button class="btn-primary" data-act="checkServer" data-arg="${s.id}">检查</button>
                    <button class="btn-danger" data-act="deleteServer" data-arg="${s.id}">删除</button>
                </div>
            </td>
        </tr>
    `;
    }).join('');
}

// 检查服务器状态
async function checkServer(id) {
    const resp = await fetch(`/api/servers/${id}/check`);
    const data = await resp.json();
    if (data.success) {
        loadServers();
        alert(`服务器状态: ${data.status}`);
    }
}

// 加载转发规则
async function loadRules() {
    const resp = await fetch('/api/rules');
    rules = await resp.json();
    renderRulesTree();
}

function renderRulesTree() {
    const container = document.getElementById('rulesTree');
    const list = [...rules];
    
    // 按服务器分组
    const groups = {};
    list.forEach(r => {
        const sn = r.server_name || '未知服务器';
        if (!groups[sn]) groups[sn] = [];
        groups[sn].push(r);
    });
    const serverNames = Object.keys(groups).sort();
    
    container.innerHTML = serverNames.map(sn => {
        const serverRules = groups[sn];
        return `
            <div class="tree-server">
                <div class="tree-server-header" data-act="toggleTreeGroup" data-arg="${esc(sn)}">
                    <span class="tree-server-icon">✿</span>
                    <span class="tree-server-name">${esc(sn)}</span>
                    <span class="tree-server-count">${serverRules.length} 条规则</span>
                    <span class="tree-arrow">▼</span>
                </div>
                <div class="tree-server-rules" id="tree-${esc(sn.replace(/'/g, "_"))}">
                    ${serverRules.map((r, idx) => renderTreeRule(r, idx)).join('')}
                </div>
            </div>
        `;
    }).join('');
}

function renderTreeRule(r, idx) {
    const usedGB = (r.traffic_used_bytes / (1024**3)).toFixed(2);
    const limitGB = r.traffic_limit_gb || 0;
    const percentage = limitGB > 0 ? Math.min((usedGB / limitGB) * 100, 100) : 0;
    const targetDisplay = (r.target_host && r.target_host !== r.target_ip) ? `${r.target_host} (${r.target_ip})` : r.target_ip;
    const trafficPercent = limitGB > 0 ? Math.min((usedGB / limitGB) * 100, 100) : 0;
    const connClass = (r.active_connections ?? 0) >= 50 ? 'conn-full' : (r.active_connections ?? 0) >= 20 ? 'conn-high' : '';
    const connConn = r.active_connections ?? 0;

    const BORDER_COLORS = ['#667eea','#f59e0b','#10b981','#ec4899','#3b82f6','#8b5cf6','#ef4444','#06b6d4'];
    const borderColor = BORDER_COLORS[idx % BORDER_COLORS.length];

    return `
        <div class="tree-rule" style="border-left-color:${borderColor}">
            <div class="tree-rule-main">
                <span class="tree-rule-port">${r.local_port}</span>
                <span class="tree-rule-arrow">→</span>
                <span class="tree-rule-target">${esc(targetDisplay)}:${r.target_port}</span>
                <span class="tree-rule-status ${r.enabled ? 'enabled' : 'disabled'}">${r.enabled ? '启用' : '禁用'}</span>
            </div>
            <div class="tree-rule-info">
                <span>流量: ${usedGB}/${limitGB > 0 ? limitGB + 'GB' : '不限'}</span>
                <span>连接: <span class="${connClass}">${connConn}</span></span>
                ${r.remark ? `<span>备注: ${esc(r.remark)}</span>` : ''}
            </div>
            ${limitGB > 0 ? `<div class="tree-rule-traffic-bar"><div class="tree-rule-traffic-fill" style="width:${trafficPercent}%;background:linear-gradient(90deg,${borderColor}cc,${borderColor})"></div></div>` : ''}
            <div class="tree-rule-actions">
                <button data-act="toggleRule" data-arg="${r.id}">${r.enabled ? '禁用' : '启用'}</button>
                <button data-act="editRule" data-arg="${r.id}">编辑</button>
                <button data-act="deleteRule" data-arg="${r.id}">删除</button>
            </div>
        </div>
    `;
}

function toggleTreeGroup(serverName) {
    const el = document.getElementById('tree-' + serverName.replace(/'/g, "_"));
    const header = el.previousElementSibling;
    if (el && header) {
        const isHidden = el.style.display === 'none';
        el.style.display = isHidden ? 'block' : 'none';
        header.classList.toggle('expanded', isHidden);
    }
}

function getFilteredSortedRules() {
    let items = [...rules];
    if (ruleFilterText) {
        const q = ruleFilterText.toLowerCase();
        items = items.filter(r => [r.server_name, r.local_port, r.target_host, r.target_ip, r.target_port, r.remark].join(' ').toLowerCase().includes(q));
    }
    items.sort((a,b) => {
        const av = a[ruleSortKey] ?? '';
        const bv = b[ruleSortKey] ?? '';
        if (av == bv) return 0;
        return ruleSortDir === 'asc' ? (av > bv ? 1 : -1) : (av < bv ? 1 : -1);
    });
    return items;
}

function setRuleSort(key) {
    if (ruleSortKey === key) ruleSortDir = ruleSortDir === 'asc' ? 'desc' : 'asc';
    else { ruleSortKey = key; ruleSortDir = 'asc'; }
    renderRules();
}

function setRuleFilter(value) {
    ruleFilterText = value.trim();
    renderRules();
    renderServerGroups();
}

// 视图切换
let rulesViewMode = 'table';
function toggleRulesView(mode) {
    rulesViewMode = mode;
    document.getElementById('rulesTableView').style.display = mode === 'table' ? 'block' : 'none';
    document.getElementById('rulesGroupView').style.display = mode === 'group' ? 'block' : 'none';
    if (mode === 'group') renderServerGroups();
}

// 渲染分组视图
function renderServerGroups() {
    const container = document.getElementById('serverGroups');
    const list = getFilteredSortedRules();
    
    // 按服务器分组
    const groups = {};
    list.forEach(r => {
        const sn = r.server_name || '未知服务器';
        if (!groups[sn]) groups[sn] = [];
        groups[sn].push(r);
    });
    
    container.innerHTML = Object.entries(groups).map(([serverName, serverRules]) => `
        <div class="server-group">
            <div class="server-group-header" data-act="toggleGroupStr" data-arg="${esc(serverName)}">
                <span class="server-group-title">🖥️ ${esc(serverName)}</span>
                <span class="server-group-count">${serverRules.length} 条规则</span>
                <span class="server-group-arrow">▼</span>
            </div>
            <div class="server-group-content" id="group-${esc(serverName.replace(/'/g, "_"))}">
                ${serverRules.map(r => renderRuleCard(r)).join('')}
            </div>
        </div>
    `).join('');
}

function renderRuleCard(r) {
    const usedGB = (r.traffic_used_bytes / (1024**3)).toFixed(2);
    const limitGB = r.traffic_limit_gb || 0;
    const percentage = limitGB > 0 ? Math.min((usedGB / limitGB) * 100, 100) : 0;
    const targetDisplay = (r.target_host && r.target_host !== r.target_ip) ? `${r.target_host} (${r.target_ip})` : r.target_ip;
    
    return `
        <div class="rule-card">
            <div class="rule-card-header">
                <span class="rule-card-title">端口 ${r.local_port} → ${r.target_port}</span>
                <span class="status-${r.enabled ? 'online' : 'offline'}">${r.enabled ? '✓ 启用' : '✗ 禁用'}</span>
            </div>
            <div class="rule-card-row">
                <span class="rule-card-label">目标</span>
                <span class="rule-card-value">${esc(targetDisplay)}:${r.target_port}</span>
            </div>
            <div class="rule-card-row">
                <span class="rule-card-label">流量</span>
                <span class="rule-card-value">${usedGB} / ${limitGB > 0 ? limitGB + ' GB' : '不限'}</span>
            </div>
            ${limitGB > 0 ? `<div class="traffic-bar"><div class="traffic-bar-fill" style="width:${percentage}%"></div></div>` : ''}
            <div class="rule-card-row">
                <span class="rule-card-label">连接数</span>
                <span class="rule-card-value">${r.active_connections ?? 0}</span>
            </div>
            ${r.remark ? `<div class="rule-card-row"><span class="rule-card-label">备注</span><span class="rule-card-value">${esc(r.remark)}</span></div>` : ''}
            <div class="rule-card-actions">
                <button class="btn-primary" data-act="toggleRule" data-arg="${r.id}">${r.enabled ? '禁用' : '启用'}</button>
                <button class="btn-success" data-act="editRule" data-arg="${r.id}">编辑</button>
                <button class="btn-danger" data-act="deleteRule" data-arg="${r.id}">删除</button>
            </div>
        </div>
    `;
}

function toggleGroup(serverName) {
    const el = document.getElementById('group-' + serverName.replace(/'/g, "_"));
    if (el) el.style.display = el.style.display === 'none' ? 'block' : 'none';
}

function toggleRulesView(mode) {
    rulesViewMode = mode;
    document.getElementById('rulesTableView').style.display = mode === 'table' ? 'block' : 'none';
    document.getElementById('rulesGroupView').style.display = mode === 'group' ? 'block' : 'none';
    document.getElementById('rulesList').style.display = 'none';
    renderRules();
}

// 渲染分组视图
function renderRulesGroup() {
    const container = document.getElementById('serverGroups');
    if (!container) return;
    
    const list = getFilteredSortedRules();
    const filterQ = ruleFilterText.toLowerCase();
    
    // 按服务器分组
    const groups = {};
    list.forEach(r => {
        if (!groups[r.server_id]) {
            groups[r.server_id] = { name: r.server_name, host: r.server_host, rules: [] };
        }
        groups[r.server_id].rules.push(r);
    });
    
    // 渲染每个服务器分组
    container.innerHTML = Object.entries(groups).map(([serverId, g]) => {
        const enabled = g.rules.filter(r => r.enabled).length;
        const total = g.rules.length;
        const conns = g.rules.reduce((sum, r) => sum + (r.active_connections || 0), 0);
        
        return `
        <div class="server-group" style="margin-bottom:16px;border:1px solid #e5e7eb;border-radius:12px;overflow:hidden;">
            <div class="server-group-header" data-act="toggleGroup" data-arg="${serverId}" style="display:flex;justify-content:space-between;align-items:center;padding:12px 16px;background:linear-gradient(135deg,#667eea,#764ba2);color:white;cursor:pointer;">
                <div>
                    <div style="font-weight:700;font-size:16px;">${esc(g.name)}</div>
                    <div style="font-size:12px;opacity:0.9;">${esc(g.host)}</div>
                </div>
                <div style="text-align:right;">
                    <div style="font-size:14px;">${enabled}/${total} 规则</div>
                    <div style="font-size:12px;">${conns} 连接</div>
                </div>
            </div>
            <div class="server-group-rules" id="group_${serverId}" style="display:none;padding:10px;background:#f8fafc;">
                <table style="width:100%;table-layout:auto;">
                    <thead>
                        <tr>
                            <th style="padding:8px;text-align:left;font-size:12px;color:#667eea;">端口</th>
                            <th style="padding:8px;text-align:left;font-size:12px;color:#667eea;">目标</th>
                            <th style="padding:8px;text-align:center;font-size:12px;color:#667eea;">状态</th>
                            <th style="padding:8px;text-align:center;font-size:12px;color:#667eea;">操作</th>
                        </tr>
                    </thead>
                    <tbody>
                        ${g.rules.map(r => {
                            const targetDisplay = (r.target_host && r.target_host !== r.target_ip) ? `${esc(r.target_host)}<br><small style="color:#666">${esc(r.target_ip)}</small>` : esc(r.target_ip);
                            return `
                            <tr style="border-bottom:1px solid #eee;">
                                <td style="padding:8px;"><strong>${r.local_port}</strong> → ${r.target_port}</td>
                                <td style="padding:8px;font-size:13px;">${targetDisplay}</td>
                                <td style="padding:8px;text-align:center;"><span class="status-${r.enabled ? 'online' : 'offline'}">${r.enabled ? '启用' : '禁用'}</span></td>
                                <td style="padding:8px;text-align:center;">
                                    <button class="btn-primary" data-act="toggleRule" data-arg="${r.id}" style="padding:4px 8px;font-size:11px;">${r.enabled ? '禁用' : '启用'}</button>
                                    <button class="btn-success" data-act="editRule" data-arg="${r.id}" style="padding:4px 8px;font-size:11px;">编辑</button>
                                </td>
                            </tr>
                            `;
                        }).join('')}
                    </tbody>
                </table>
            </div>
        </div>
        `;
    }).join('') || '<div style="padding:20px;text-align:center;color:#999;">暂无规则</div>';
}

// 展开/收起服务器分组
function toggleGroup(serverId) {
    const el = document.getElementById('group_' + serverId);
    if (el) {
        el.style.display = el.style.display === 'none' ? 'block' : 'none';
    }
}

// 渲染规则表格
function renderRules() {
    const tbody = document.querySelector('#rulesTable tbody');
    const list = getFilteredSortedRules();
    
    // 桌面端表格
    tbody.innerHTML = list.map(r => {
        const usedGB = (r.traffic_used_bytes / (1024**3)).toFixed(2);
        const limitGB = r.traffic_limit_gb || 0;
        const percentage = limitGB > 0 ? Math.min((usedGB / limitGB) * 100, 100) : 0;
        
        return `
        <tr>
            <td><input type="checkbox" data-change="toggleRuleSelection" data-arg="${r.id}" ${selectedRuleIds.has(r.id) ? 'checked' : ''}></td>
            <td class="col-server cell">${esc(r.server_name)}</td>
            <td class="col-port cell">${r.local_port}</td>
            <td class="col-ip cell">${esc((r.target_host && r.target_host !== r.target_ip) ? `${r.target_host} (${r.target_ip})` : r.target_ip)}</td>
            <td class="col-port cell">${r.target_port}</td>
            <td class="col-remark cell" title="${esc(r.remark || '')}">${esc((r.remark || '').slice(0, 12))}</td>
            <td class="col-port cell">${limitGB > 0 ? limitGB + ' GB' : '不限制'}</td>
            <td class="col-traffic">
                ${usedGB} GB
                ${limitGB > 0 ? `<div class="traffic-bar"><div class="traffic-bar-fill" style="width:${percentage}%"></div></div>` : ''}
            </td>
            <td class="col-port cell">${r.active_connections ?? 0}</td>
            <td class="col-port cell">${r.enabled ? '<span style="color:#00f2fe;font-weight:600">✓ 启用</span>' : '<span style="color:#f5576c;font-weight:600">✗ 禁用</span>'}</td>
            <td class="col-created cell">${formatCreatedAt(r.created_at)}</td>
            <td class="col-actions">
                <div class="action-group" style="justify-content:center">
                    <button class="btn-primary" data-act="toggleRule" data-arg="${r.id}">${r.enabled ? '禁用' : '启用'}</button>
                    <button class="btn-success" data-act="editRule" data-arg="${r.id}">编辑</button>
                    <button class="btn-danger" data-act="deleteRule" data-arg="${r.id}">删除</button>
                </div>
            </td>
        </tr>
    `}).join('');
    
    // 移动端卡片列表
    const rulesList = document.getElementById('rulesList');
    if (rulesList) {
        rulesList.innerHTML = list.map(r => {
            const usedGB = (r.traffic_used_bytes / (1024**3)).toFixed(2);
            const limitGB = r.traffic_limit_gb || 0;
            const percentage = limitGB > 0 ? Math.min((usedGB / limitGB) * 100, 100) : 0;
            const targetDisplay = (r.target_host && r.target_host !== r.target_ip) ? `${r.target_host} (${r.target_ip})` : r.target_ip;
            
            return `
            <div class="rule-card">
                <div class="rule-card-header">
                    <span class="rule-card-title">端口 ${r.local_port} → ${r.target_port}</span>
                    <span class="status-${r.enabled ? 'online' : 'offline'}">${r.enabled ? '启用' : '禁用'}</span>
                </div>
                <div class="rule-card-row">
                    <span class="rule-card-label">服务器</span>
                    <span class="rule-card-value">${esc(r.server_name)}</span>
                </div>
                <div class="rule-card-row">
                    <span class="rule-card-label">目标</span>
                    <span class="rule-card-value">${esc(targetDisplay)}:${r.target_port}</span>
                </div>
                <div class="rule-card-row">
                    <span class="rule-card-label">流量</span>
                    <span class="rule-card-value">${usedGB} / ${limitGB > 0 ? limitGB + ' GB' : '不限'}</span>
                </div>
                ${limitGB > 0 ? `<div class="traffic-bar"><div class="traffic-bar-fill" style="width:${percentage}%"></div></div>` : ''}
                <div class="rule-card-row">
                    <span class="rule-card-label">连接数</span>
                    <span class="rule-card-value">${r.active_connections ?? 0}</span>
                </div>
                ${r.remark ? `<div class="rule-card-row"><span class="rule-card-label">备注</span><span class="rule-card-value">${esc(r.remark)}</span></div>` : ''}
                <div class="rule-card-actions">
                    <button class="btn-primary" data-act="toggleRule" data-arg="${r.id}">${r.enabled ? '禁用' : '启用'}</button>
                    <button class="btn-success" data-act="editRule" data-arg="${r.id}">编辑</button>
                    <button class="btn-danger" data-act="deleteRule" data-arg="${r.id}">删除</button>
                </div>
            </div>
            `;
        }).join('');
    }
    
    // 同时渲染分组视图
    renderRulesGroup();
}

function formatCreatedAt(value) {
    if (!value) return '';
    const d = new Date(value);
    if (Number.isNaN(d.getTime())) return value;
    const y = d.getFullYear();
    const m = String(d.getMonth() + 1).padStart(2, '0');
    const day = String(d.getDate()).padStart(2, '0');
    const hh = String(d.getHours()).padStart(2, '0');
    const mm = String(d.getMinutes()).padStart(2, '0');
    const ss = String(d.getSeconds()).padStart(2, '0');
    return `${y}-${m}-${day}<br>${hh}:${mm}:${ss}`;
}

// 显示添加服务器模态框
function showAddServerModal() {
    document.getElementById('addServerModal').style.display = 'block';
}

// 显示添加规则模态框
function showAddRuleModal() {
    const select = document.getElementById('ruleServer');
    select.innerHTML = servers.map(s => 
        `<option value="${s.id}">${esc(s.name)} (${esc(s.host)})</option>`
    ).join('');
    document.getElementById('addRuleModal').style.display = 'block';
}

// 关闭模态框
function openModal(id) {
    document.getElementById(id).style.display = 'block';
}

function closeModal(id) {
    document.getElementById(id).style.display = 'none';
    if (id === 'logsModal' && autoLogsTimer) {
        clearInterval(autoLogsTimer);
        autoLogsTimer = null;
        const btn = document.getElementById('autoLogsBtn');
        if (btn) btn.textContent = '自动刷新';
    }
}

let autoLogsTimer = null;

function showLogsModal() {
    document.getElementById('logsModal').style.display = 'block';
    loadLogs();
}

function toggleAutoLogs() {
    const btn = document.getElementById('autoLogsBtn');
    if (autoLogsTimer) {
        clearInterval(autoLogsTimer);
        autoLogsTimer = null;
        btn.textContent = '自动刷新';
        return;
    }
    autoLogsTimer = setInterval(loadLogs, 2000);
    btn.textContent = '停止刷新';
}

async function loadLogs() {
    const resp = await fetch('/api/logs');
    const data = await resp.json();
    const el = document.getElementById('logsContent');
    if (data.success) {
        el.textContent = data.lines.join('\n');
        el.scrollTop = el.scrollHeight;
    } else {
        el.textContent = data.error || '读取日志失败';
    }
}

// 添加服务器
async function addServer() {
    const editId = document.getElementById('serverEditId')?.value;
    const data = {
        name: document.getElementById('serverName').value,
        host: document.getElementById('serverHost').value,
        port: parseInt(document.getElementById('serverPort').value),
        token: document.getElementById('serverToken').value
    };
    
    const resp = editId ? await fetch(`/api/servers/${editId}`, {method:'PUT', headers:{'Content-Type':'application/json','X-CSRF-Token':csrfToken}, body: JSON.stringify(data)}) : await postWithCsrf('/api/servers', data);
    
    if (resp.ok) {
        const result = await resp.json();
        closeModal('addServerModal');
        loadServers();
        
        // 新增服务器后显示一键部署命令
        if (!editId && result.deploy_cmd) {
            showDeployCommand(result.deploy_cmd);
        } else {
            showSuccess(editId ? '服务器更新成功' : '服务器添加成功');
        }
    } else {
        const err = await resp.json();
        showError('添加失败', '#f5576c', 5000, err.error || '未知错误');
    }
}

// 删除服务器
async function deleteServer(id) {
    if (!confirm('确定删除此服务器？')) return;
    await deleteWithCsrf(`/api/servers/${id}`);
    loadServers();
    loadRules().then(() => { loadTrafficSummary(); loadConnectionsSummary(); });
}

// 添加规则
async function addRule() {
    const data = {
        server_id: parseInt(document.getElementById('ruleServer').value),
        local_port: parseInt(document.getElementById('ruleLocalPort').value),
        target_ip: document.getElementById('ruleTargetIp').value,
        target_host: document.getElementById('ruleTargetIp').value,
        target_port: parseInt(document.getElementById('ruleTargetPort').value),
        remark: document.getElementById('ruleRemark').value || '',
        traffic_limit_gb: parseInt(document.getElementById('ruleTrafficLimit').value) || 0
    };
    
    const resp = await postWithCsrf('/api/rules', data);
    
    if (resp.ok) {
        closeModal('addRuleModal');
        loadRules();
        showSuccess('规则添加成功！🎉');
    } else {
        const err = await resp.json();
        showError('添加失败', '#f5576c', 5000, err.error || '未知错误');
    }
}

// 成功提示
function showSuccess(message) {
    showToast(message, '#00f2fe');
}

// 一键部署命令提示
function showDeployCommand(cmd) {
    const modal = document.createElement('div');
    modal.className = 'modal';
    modal.style.display = 'block';
    modal.innerHTML = `
        <div class="modal-content" style="max-width:600px">
            <div class="modal-header">
                <h2>一键部署 Agent</h2>
                <span class="close" data-act="closeModalSelf">&times;</span>
            </div>
            <div style="padding:20px">
                <p style="margin-bottom:10px">复制以下命令到目标服务器执行：</p>
                <pre style="background:#f5f5f5;padding:15px;border-radius:5px;overflow-x:auto;word-break:break-all">${esc(cmd)}</pre>
                <p style="margin-top:15px;color:#666;font-size:12px">该命令会自动下载并启动 SNAT Agent</p>
            </div>
        </div>
    `;
    document.body.appendChild(modal);
}

// 错误提示
function showError(message) {
    showToast(message, '#f5576c');
}

// Toast 提示
function showToast(message, color, duration = 3000, detail = '') {
    const toast = document.createElement('div');
    toast.className = 'toast';
    toast.style.cssText = `position:fixed;top:20px;right:20px;background:${color};color:#fff;padding:14px 16px;border-radius:10px;box-shadow:0 4px 12px rgba(0,0,0,0.25);z-index:10000;max-width:420px;display:flex;gap:10px;align-items:flex-start`;
    toast.innerHTML = `<div style="font-size:18px">${color === '#f5576c' ? '❌' : color === '#ffa500' ? '⚠️' : '✅'}</div><div style="flex:1"><div>${esc(message)}</div>${detail ? `<div style="margin-top:6px;font-size:12px;opacity:.9">${esc(detail)}</div>` : ''}</div><button style="background:none;border:none;color:#fff;font-size:18px;cursor:pointer">×</button>`;
    toast.querySelector('button').onclick = () => toast.remove();
    document.body.appendChild(toast);
    setTimeout(() => toast.remove(), duration);
}

// 删除规则
async function deleteRule(id) {
    const confirmText = prompt('删除规则属于危险操作，输入 DELETE 确认');
    if (confirmText !== 'DELETE') return;
    const resp = await deleteWithCsrf(`/api/rules/${id}`);
    if (resp.ok) { showSuccess('规则已删除'); loadRules().then(() => { loadTrafficSummary(); loadConnectionsSummary(); }); }
    else { const err = await resp.json().catch(() => ({error:'删除失败'})); showError(err.error || '删除失败'); }
}

// 编辑规则
function editRule(id) {
    const rule = rules.find(r => r.id === id);
    if (!rule) return;
    
    document.getElementById('editRuleId').value = rule.id;
    document.getElementById('editRuleLocalPort').value = rule.local_port;
    document.getElementById('editRuleTargetIp').value = rule.target_host || rule.target_ip;
    document.getElementById('editRuleTargetPort').value = rule.target_port;
    document.getElementById('editRuleRemark').value = rule.remark || '';
    document.getElementById('editRuleTrafficLimit').value = rule.traffic_limit_gb || 0;
    
    openModal('editRuleModal');
}

// 保存编辑
async function saveEditRule() {
    const id = document.getElementById('editRuleId').value;
    const data = {
        local_port: parseInt(document.getElementById('editRuleLocalPort').value),
        target_ip: document.getElementById('editRuleTargetIp').value,
        target_host: document.getElementById('editRuleTargetIp').value,
        target_port: parseInt(document.getElementById('editRuleTargetPort').value),
        remark: document.getElementById('editRuleRemark').value || '',
        traffic_limit_gb: parseInt(document.getElementById('editRuleTrafficLimit').value) || 0
    };
    
    const resp = await fetch(`/api/rules/${id}`, {
        method: 'PUT',
        headers: {
            'Content-Type': 'application/json',
            'X-CSRF-Token': csrfToken
        },
        body: JSON.stringify(data)
    });
    
    if (resp.ok) {
        closeModal('editRuleModal');
        loadRules().then(() => { loadTrafficSummary(); loadConnectionsSummary(); });
        const data = await resp.json().catch(() => ({success:true}));
        showSuccess(data.warning ? '更新成功（Agent 同步异常）' : '更新成功！🎉', '#00f2fe', 4000, data.warning || '');
    } else {
        const err = await resp.json();
        showError('更新失败', '#f5576c', 5000, err.error || '未知错误');
    }
}

// 启用/禁用规则
async function toggleRule(id) {
    const resp = await postWithCsrf(`/api/rules/${id}/toggle`, {});
    const data = await resp.json();
    if (data.success) {
        loadRules();
        showSuccess(data.enabled ? '规则已启用' : '规则已禁用');
    } else {
        showError('操作失败: ' + (data.error || '未知错误'));
    }
}

// 登出
function logout() {
    if (confirm('确定要登出吗？')) {
        window.location.href = '/logout';
    }
}

// 显示修改密码模态框
function showChangePasswordModal() {
    document.getElementById('changePasswordModal').style.display = 'block';
}

// 修改密码
async function changePassword() {
    const oldPassword = document.getElementById('oldPassword').value;
    const newPassword = document.getElementById('newPassword').value;
    const confirmPassword = document.getElementById('confirmPassword').value;
    
    if (newPassword !== confirmPassword) {
        alert('两次密码不一致');
        return;
    }
    
    if (newPassword.length < 8) {
        alert('密码至少8位');
        return;
    }
    
    const resp = await postWithCsrf('/api/change_password', {
        old_password: oldPassword, 
        new_password: newPassword
    });
    
    const data = await resp.json();
    if (data.success) {
        alert('密码修改成功，请重新登录');
        window.location.href = '/logout';
    } else {
        alert('修改失败: ' + data.error);
    }
}

// 显示设置模态框
async function showSettingsModal() {
    const resp = await fetch('/api/settings');
    const data = await resp.json();
    document.getElementById('ipWhitelist').value = data.ip_whitelist.join('\n');
    document.getElementById('forceHttps').checked = !!data.force_https;
    document.getElementById('settingsModal').style.display = 'block';
}

// 保存设置
async function saveSettings() {
    const whitelist = document.getElementById('ipWhitelist').value
        .split('\n')
        .map(ip => ip.trim())
        .filter(ip => ip);
    const force_https = document.getElementById('forceHttps').checked;
    const [r1, r2] = await Promise.all([
        postWithCsrf('/api/settings/ip_whitelist', {whitelist}),
        postWithCsrf('/api/settings/https', {force_https})
    ]);
    const d1 = await r1.json();
    const d2 = await r2.json();
    if (d1.success && d2.success) {
        showSuccess('设置已保存');
        closeModal('settingsModal');
    } else {
        showError('保存失败');
    }
}

// 诊断功能
async function showDiagModal() {
    document.getElementById('diagModal').style.display = 'block';
    document.getElementById('diagResults').innerHTML = '<p style="color:#888">正在检查...</p>';
    
    const resp = await fetch('/api/diag');
    const data = await resp.json();
    
    let html = '<div style="display:grid;gap:15px">';
    for (const server of data.servers) {
        const statusColor = server.status === 'healthy' ? '#00f2fe' : 
                           server.status === 'error' ? '#ffa500' : '#f5576c';
        const statusText = server.status === 'healthy' ? '✓ 正常' :
                          server.status === 'error' ? '⚠ 异常' : '✗ 离线';
        
        html += `<div style="background:rgba(255,255,255,0.05);padding:15px;border-radius:8px;border-left:3px solid ${statusColor}">`;
        html += `<h3 style="margin:0 0 10px 0;color:${statusColor}">${esc(server.server_name)} ${statusText}</h3>`;
        
        if (server.status === 'healthy') {
            html += `<p style="margin:5px 0">IP转发: ${server.ip_forward ? '✓ 已启用' : '✗ 未启用'}</p>`;
            html += `<p style="margin:5px 0">iptables: ${server.iptables_ok ? '✓ 正常' : '✗ 异常'}</p>`;
            html += `<p style="margin:5px 0">Docker: ${server.docker_ok ? '✓ 正常' : '⚠ 可能异常'}</p>`;
        } else {
            html += `<p style="color:#f5576c">错误: ${esc(server.error)}</p>`;
        }
        html += '</div>';
    }
    html += '</div>';
    
    document.getElementById('diagResults').innerHTML = html;
}

// 流量告警检查
function checkTrafficAlerts() {
    const alerts = [];
    for (const rule of rules) {
        if (rule.traffic_limit_gb > 0) {
            const usedGB = rule.traffic_used_bytes / (1024**3);
            const percentage = (usedGB / rule.traffic_limit_gb) * 100;
            
            if (percentage >= 90 && rule.enabled) {
                alerts.push(`规则 ${rule.server_name}:${rule.local_port} 流量已达 ${percentage.toFixed(1)}%`);
            }
        }
        
        // 检查流量为0的启用规则
        if (rule.enabled && rule.traffic_used_bytes === 0) {
            const createdTime = new Date(rule.created_at).getTime();
            const now = Date.now();
            if (now - createdTime > 5 * 60 * 1000) { // 创建超过5分钟
                alerts.push(`规则 ${rule.server_name}:${rule.local_port} 无流量统计，可能异常`);
            }
        }
    }
    
    if (alerts.length > 0) {
        showAlert(alerts.join('\n'));
    }
}

// 显示告警
function showAlert(message) {
    const alertDiv = document.getElementById('alertBox');
    if (!alertDiv) {
        const div = document.createElement('div');
        div.id = 'alertBox';
        div.style.cssText = 'position:fixed;top:20px;right:20px;background:#ffa500;color:#000;padding:15px 20px;border-radius:8px;box-shadow:0 4px 12px rgba(0,0,0,0.3);max-width:400px;z-index:10000';
        div.innerHTML = `<strong>⚠ 告警</strong><br>${esc(message).replace(/\n/g, '<br>')}`;
        document.body.appendChild(div);
        
        setTimeout(() => div.remove(), 10000);
    }
}


async function createBackup() {
    const resp = await postWithCsrf('/api/backup', {});
    const data = await resp.json();
    if (data.success) alert(`备份已创建: ${data.path}`);
    else alert(data.error || '备份失败');
}


function toggleRuleSelection(id, checked) {
    if (checked) selectedRuleIds.add(id);
    else selectedRuleIds.delete(id);
    updateBulkBar();
}

function toggleAllRules(checked) {
    selectedRuleIds = checked ? new Set(getFilteredSortedRules().map(r => r.id)) : new Set();
    updateBulkBar();
    renderRules();
}

async function bulkAction(action) {
    if (selectedRuleIds.size === 0) return alert('请先选择规则');
    if (action === 'delete') { const text = prompt(`确定删除 ${selectedRuleIds.size} 条规则？输入 DELETE 确认`); if (text !== 'DELETE') return; }
    const resp = await postWithCsrf('/api/rules/bulk', {action, rule_ids: Array.from(selectedRuleIds)});
    const data = await resp.json();
    if (data.success) {
        showSuccess(`批量操作完成：成功 ${data.affected.length} 条，失败 ${data.failed.length} 条`);
        selectedRuleIds.clear();
        updateBulkBar();
        loadRules().then(() => { loadTrafficSummary(); loadConnectionsSummary(); });
    } else showError(data.error || '批量操作失败');
}

async function bulkCheckServers() {
    const resp = await postWithCsrf('/api/servers/bulk_check', {});
    const data = await resp.json();
    if (data.success) {
        const ok = data.results.filter(x => x.ok).length;
        const fail = data.results.length - ok;
        showSuccess(`批量检查完成：成功 ${ok} 台，失败 ${fail} 台`);
        const el = document.getElementById('bulkResult');
        if (el) el.innerHTML = data.results.map(x => `<div>${esc(x.name)}: ${x.ok ? '✅ OK' : '❌ ' + esc(x.error || ('HTTP ' + (x.status_code ?? 'ERR')))}</div>`).join('');
    }
}

async function loadTrafficSummary() {
    const resp = await fetch('/api/traffic/summary');
    const data = await resp.json();
    const el = document.getElementById('trafficSummary');
    if (!el) return;
    if (!data.success) { el.innerHTML = '流量汇总加载失败'; return; }

    const totalGB = (data.total_bytes / (1024**3)).toFixed(2);
    const labels = data.top_rules.map(r => (r.remark && r.remark.trim()) ? r.remark.trim() : String(r.local_port));
    const values = data.top_rules.map(r => Number((r.traffic_used_bytes / (1024**3)).toFixed(2)));
    const topLabels = labels.map(x => x.length > 14 ? (x.slice(0, 14) + '…') : x);

    el.innerHTML = `<div style="display:grid;gap:8px;color:#1f2937;font-weight:700"><div>总流量：<b style="color:#111827">${totalGB} GB</b></div><div>规则数：<b style="color:#111827">${data.rules_count}</b>，启用：<b style="color:#111827">${data.enabled_count}</b></div><div style="font-size:12px;color:#374151;word-break:break-word;line-height:1.45">Top 10：<span style="color:#111827">${esc(topLabels.join(' / ')) || '暂无'}</span></div><canvas id="trafficChart" height="170"></canvas></div>`;

    const canvas = document.getElementById('trafficChart');
    if (!(canvas && labels.length)) return;

    const ctx = canvas.getContext('2d');
    const isMobile = window.innerWidth <= 768;
    const parentW = canvas.parentElement.clientWidth;
    const w = canvas.width = Math.max(260, parentW - 12);
    const h = canvas.height = isMobile ? 200 : 170;

    ctx.clearRect(0, 0, w, h);

    const max = Math.max(...values, 1);
    const n = labels.length;
    const gap = isMobile ? 6 : 10;
    const plotL = 10;
    const plotR = 10;
    const plotW = w - plotL - plotR;
    const barW = Math.max(14, Math.floor((plotW - gap * (n - 1)) / Math.max(n, 1)));
    const step = barW + gap;
    const chartBottom = h - (isMobile ? 54 : 36);
    const chartTop = 26;
    const chartH = Math.max(80, chartBottom - chartTop);

    ctx.textBaseline = 'alphabetic';
    ctx.lineWidth = 1;

    values.forEach((v, i) => {
        const x = plotL + i * step;
        const bh = Math.max(4, (v / max) * chartH);
        const y = chartBottom - bh;

        ctx.fillStyle = '#667eea';
        ctx.fillRect(x, y, barW, bh);

        ctx.fillStyle = '#111827';
        ctx.font = isMobile ? 'bold 10px sans-serif' : 'bold 11px sans-serif';
        ctx.textAlign = 'center';
        ctx.fillText(String(v) + 'G', x + barW / 2, Math.max(12, y - 4));

        const raw = labels[i] || '';
        const clipped = raw.length > 10 ? (raw.slice(0, 10) + '…') : raw;

        if (isMobile) {
            const maxCharsPerLine = Math.max(2, Math.floor((barW + gap) / 7));
            const line1 = clipped.slice(0, maxCharsPerLine);
            const line2 = clipped.slice(maxCharsPerLine, maxCharsPerLine * 2);
            const cx = x + barW / 2;
            ctx.fillStyle = '#374151';
            ctx.font = '10px sans-serif';
            ctx.textAlign = 'center';
            ctx.fillText(line1, cx, h - 20);
            if (line2) ctx.fillText(line2, cx, h - 8);
        } else {
            ctx.fillStyle = '#374151';
            ctx.font = '11px sans-serif';
            ctx.textAlign = 'left';
            ctx.fillText(clipped, x, h - 8);
        }
    });
}



async function loadAuditLogs() {
    const resp = await fetch('/api/audit_logs');
    const data = await resp.json();
    const el = document.getElementById('auditContent');
    if (!el) return;
    el.textContent = data.success ? data.items.map(x => `${x.created_at} | ${x.username}@${x.client_ip} | ${x.action} | ${x.target} | ${x.status} | ${x.detail||''}`).join('\n') : (data.error || '加载失败');
}

async function loadBackups() {
    const resp = await fetch('/api/backup/list');
    const data = await resp.json();
    const el = document.getElementById('backupList');
    if (!el) return;
    el.innerHTML = data.success ? data.items.map(x => `<div>${esc(x.name)} <button class="btn-danger" data-act="restoreBackup" data-arg="${esc(x.path)}">恢复</button></div>`).join('') : '加载失败';
}

async function restoreBackup(path) {
    const text = prompt('恢复备份将覆盖当前数据库，输入 RESTORE 确认');
    if (text !== 'RESTORE') return;
    const resp = await postWithCsrf('/api/backup/restore', {path, confirm: 'RESTORE'});
    const data = await resp.json();
    if (data.success) showSuccess('备份恢复成功，请刷新页面'); else showError(data.error || '恢复失败');
}

async function createSnapshot() {
    const reason = prompt('输入快照备注', 'manual');
    const resp = await postWithCsrf('/api/snapshots', {reason: reason || 'manual'});
    const data = await resp.json();
    if (data.success) { showSuccess('快照已创建 #' + data.id); loadSnapshots(); }
}

async function loadSnapshots() {
    const resp = await fetch('/api/snapshots');
    const data = await resp.json();
    const el = document.getElementById('snapshotList');
    if (!el) return;
    el.innerHTML = data.success ? data.items.map(x => `<div>#${x.id} ${x.created_at} <b>${esc(x.reason || 'manual')}</b> <button class="btn-danger" data-act="restoreSnapshot" data-arg="${x.id}">恢复</button> <button class="btn-danger" data-act="deleteSnapshot" data-arg="${x.id}">删除</button></div>`).join('') : '加载失败';
}

async function restoreSnapshot(id) {
    const text = prompt('恢复快照会覆盖当前规则，输入 RESTORE 确认');
    if (text !== 'RESTORE') return;
    const resp = await postWithCsrf(`/api/snapshots/${id}/restore`, {confirm: 'RESTORE'});
    const data = await resp.json();
    if (data.success) { showSuccess('快照恢复成功'); loadRules().then(() => { loadTrafficSummary(); loadConnectionsSummary(); }); }
}

async function exportData(type) {
    window.open(`/api/export/${type}`, '_blank');
}

async function importJson(type) {
    const text = prompt('粘贴 JSON 数组');
    if (!text) return;
    let rows;
    try { rows = JSON.parse(text); } catch { return alert('JSON 格式错误'); }
    const resp = await postWithCsrf(`/api/import/${type}`, {rows});
    const data = await resp.json();
    if (data.success) { showSuccess(`导入成功 ${data.inserted} 条`); loadServers(); loadRules().then(() => { loadTrafficSummary(); loadConnectionsSummary(); }); }
}

async function loadAlertSettings() {
    const resp = await fetch('/api/settings/alerts');
    const data = await resp.json();
    const token = document.getElementById('tgBotToken');
    const chat = document.getElementById('tgChatId');
    const sec = document.getElementById('alertOfflineSeconds');
    // 出于安全，后端不回显 Bot Token 明文；这里用占位文字提示是否已配置，留空提交则保持原值不变。
    if (token) { token.value = ''; token.placeholder = data.tg_bot_token_set ? '已配置（留空＝不修改）' : '未配置'; }
    if (chat) chat.value = data.tg_chat_id || '';
    if (sec) sec.value = data.offline_seconds || 300;
}

async function saveAlertSettings() {
    const tg_bot_token = document.getElementById('tgBotToken').value;
    const tg_chat_id = document.getElementById('tgChatId').value;
    const offline_seconds = parseInt(document.getElementById('alertOfflineSeconds').value || '300');
    const resp = await postWithCsrf('/api/settings/alerts', {tg_bot_token, tg_chat_id, offline_seconds});
    const data = await resp.json();
    if (data.success) showSuccess('告警设置已保存'); else showError(data.error || '保存失败');
}

async function testAlert() {
    const resp = await postWithCsrf('/api/alerts/test', {});
    const data = await resp.json();
    if (data.success) showSuccess('测试告警已发送'); else showError(data.detail || '发送失败');
}

async function checkAlerts() {
    const resp = await postWithCsrf('/api/alerts/check', {});
    const data = await resp.json();
    const el = document.getElementById('alertResult');
    if (el) el.innerHTML = data.alerts.map(x => `<div>${esc(x.server)}: ${x.ok ? '✅' : '❌ ' + esc(x.detail)}</div>`).join('') || '无告警';
}


function updateBulkBar() {
    const bar = document.getElementById('bulkBar');
    const count = document.getElementById('selectedCount');
    if (!bar || !count) return;
    count.textContent = selectedRuleIds.size;
    bar.style.display = selectedRuleIds.size > 0 ? 'block' : 'none';
}


async function reconcileRules() {
    const resp = await postWithCsrf('/api/rules/reconcile', {});
    const data = await resp.json();
    if (data.success) showSuccess(`一致性检查完成：${data.results.length} 条`);
    else showError(data.error || '检查失败');
}

async function reapplyRules() {
    const text = prompt('重新下发会覆盖 agent 当前规则，输入 REAPPLY 确认');
    if (text !== 'REAPPLY') return;
    const resp = await postWithCsrf('/api/restore/reapply', {});
    const data = await resp.json();
    if (data.success) showSuccess(`重新下发完成：${data.results.length} 条`);
    else showError(data.error || '重新下发失败');
}


function editServer(id) {
    const s = servers.find(x => x.id === id);
    if (!s) return;
    document.getElementById('serverEditId').value = s.id;
    document.getElementById('serverName').value = s.name;
    document.getElementById('serverHost').value = s.host;
    document.getElementById('serverPort').value = s.port;
    document.getElementById('serverToken').value = '';
    openModal('addServerModal');
}


async function deleteSnapshot(id) {
    const text = prompt('删除快照不可恢复，输入 DELETE 确认');
    if (text !== 'DELETE') return;
    const resp = await deleteWithCsrf(`/api/snapshots/${id}`);
    const data = await resp.json();
    if (data.success) { showSuccess('快照已删除'); loadSnapshots(); }
}

async function initTopForceHttpsToggle() {
    const el = document.getElementById('forceHttpsTop');
    if (!el) return;
    try {
        const resp = await fetch('/api/settings');
        const data = await resp.json();
        el.checked = !!data.force_https;
    } catch (e) {}
}

async function saveForceHttpsTop(checked) {
    const resp = await postWithCsrf('/api/settings/https', {force_https: checked});
    const data = await resp.json();
    if (data.success) {
        const modal = document.getElementById('forceHttps');
        if (modal) modal.checked = checked;
        showSuccess('HTTPS 设置已保存');
    } else {
        showError('HTTPS 设置保存失败');
    }
}


async function loadConnectionsSummary() {
    try {
        await postWithCsrf('/api/check_all_connections', {});
        const resp = await fetch('/api/connections/summary');
        if (!resp.ok) throw new Error('API error');
        const data = await resp.json();
        const map = new Map((data.items || []).map(i => [i.rule_id ?? i.id, i.active_connections]));
        rules = rules.map(r => ({...r, active_connections: map.get(r.id) ?? 0}));
        // 不再显示总连接数，让连接数显示在各规则卡片中
        renderRules();
    } catch (e) {
        console.error('连接数加载失败:', e);
    }
}


// ---------------------------------------------------------------------------
// 事件委托调度器（CSP 加固：移除所有内联 onclick/onchange，改由 data-act 分发）
// ---------------------------------------------------------------------------
// 目的：让 CSP 的 script-src 去掉 'unsafe-inline'。所有元素用 data-act="函数名"
// 声明行为，参数放在 data-arg / data-arg2（字符串）。这样页面里不再有任何内联脚本，
// 一旦出现 XSS 注入的 <script>/onerror 也会被 CSP 直接拦截，形成第二道防线。
const ACTION_HANDLERS = {
    // 无参
    showSettingsModal: () => showSettingsModal(),
    showDiagModal: () => showDiagModal(),
    showAddServerModal: () => showAddServerModal(),
    showAddRuleModal: () => showAddRuleModal(),
    logout: () => logout(),
    bulkCheckServers: () => bulkCheckServers(),
    toggleAutoLogs: () => toggleAutoLogs(),
    testAlert: () => testAlert(),
    showLogsModal: () => showLogsModal(),
    showChangePasswordModal: () => showChangePasswordModal(),
    saveSettings: () => saveSettings(),
    saveEditRule: () => saveEditRule(),
    saveAlertSettings: () => saveAlertSettings(),
    reconcileRules: () => reconcileRules(),
    reapplyRules: () => reapplyRules(),
    loadSnapshots: () => loadSnapshots(),
    loadLogs: () => loadLogs(),
    loadBackups: () => loadBackups(),
    loadAuditLogs: () => loadAuditLogs(),
    createSnapshot: () => createSnapshot(),
    checkAlerts: () => checkAlerts(),
    changePassword: () => changePassword(),
    addServer: () => addServer(),
    addRule: () => addRule(),
    // 带字符串参数
    bulkAction: (el) => bulkAction(el.dataset.arg),
    importJson: (el) => importJson(el.dataset.arg),
    exportData: (el) => exportData(el.dataset.arg),
    closeModal: (el) => closeModal(el.dataset.arg),
    closeModalSelf: (el) => { const m = el.closest('.modal'); if (m) m.remove(); },
    toggleGroupStr: (el) => toggleGroup(el.dataset.arg),
    toggleTreeGroup: (el) => toggleTreeGroup(el.dataset.arg),
    restoreBackup: (el) => restoreBackup(el.dataset.arg),
    // 带数字参数
    checkServer: (el) => checkServer(Number(el.dataset.arg)),
    deleteRule: (el) => deleteRule(Number(el.dataset.arg)),
    deleteServer: (el) => deleteServer(Number(el.dataset.arg)),
    deleteSnapshot: (el) => deleteSnapshot(Number(el.dataset.arg)),
    editRule: (el) => editRule(Number(el.dataset.arg)),
    editServer: (el) => editServer(Number(el.dataset.arg)),
    restoreSnapshot: (el) => restoreSnapshot(Number(el.dataset.arg)),
    toggleGroup: (el) => toggleGroup(Number(el.dataset.arg)),
    toggleRule: (el) => toggleRule(Number(el.dataset.arg)),
};

document.addEventListener('click', (e) => {
    const el = e.target.closest('[data-act]');
    if (!el) return;
    const fn = ACTION_HANDLERS[el.dataset.act];
    if (fn) { e.preventDefault(); fn(el); }
});

document.addEventListener('change', (e) => {
    const el = e.target.closest('[data-change]');
    if (!el) return;
    if (el.dataset.change === 'toggleRuleSelection') {
        toggleRuleSelection(Number(el.dataset.arg), el.checked);
    } else if (el.dataset.change === 'saveForceHttpsTop') {
        saveForceHttpsTop(el.checked);
    }
});

document.addEventListener('submit', (e) => {
    const el = e.target.closest('[data-submit]');
    if (!el) return;
    e.preventDefault();
    if (el.dataset.submit === 'addServer') addServer();
    else if (el.dataset.submit === 'addRule') addRule();
});
