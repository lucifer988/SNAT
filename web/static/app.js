// SNAT Manager - 前端逻辑

// HTML 转义：所有用户可控字段（服务器名/地址、备注、target_host、后端回传的错误文本等）
// 在拼入 innerHTML 前必须经过 esc()，防止存储型/反射型 XSS。
function escapeHtml(v) {
    return String(v ?? '').replace(/[&<>"'`]/g, ch => ({
        '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;', '`': '&#96;'
    })[ch]);
}
const esc = escapeHtml;

function formatBytes(bytes) {
    const n = Number(bytes || 0);
    if (!n) return '0 B';
    const k = 1024;
    const sizes = ['B', 'KB', 'MB', 'GB', 'TB'];
    const i = Math.min(Math.floor(Math.log(n) / Math.log(k)), sizes.length - 1);
    return `${parseFloat((n / Math.pow(k, i)).toFixed(2))} ${sizes[i]}`;
}

function formatUsedGB(bytes) {
    return (Number(bytes || 0) / (1024 ** 3)).toFixed(2);
}

function getTrafficDisplay(usedBytes, limitGb) {
    const usedGB = formatUsedGB(usedBytes);
    const limit = Number(limitGb || 0);
    if (limit <= 0) {
        return {
            usedGB,
            unlimited: true,
            percent: 100,
            limitText: '∞',
            inlineText: `${usedGB} / ∞`,
            summaryText: `${usedGB}/∞`,
            barClass: 'unlimited'
        };
    }
    const percent = Math.min((Number(usedGB) / limit) * 100, 100);
    return {
        usedGB,
        unlimited: false,
        percent,
        limitText: `${limit} GB`,
        inlineText: `${usedGB} / ${limit} GB`,
        summaryText: `${usedGB}/${limit}GB`,
        barClass: percent >= 80 ? 'warning' : 'normal'
    };
}

let servers = [];
let rules = [];
let csrfToken = '';
let selectedRuleIds = new Set();
let ruleSortKey = 'sort_order';
let ruleSortDir = 'asc';
let ruleFilterText = '';

// 页面加载时初始化
document.addEventListener('DOMContentLoaded', async () => {
    await getCsrfToken();
    await initTopForceHttpsToggle();
    loadServers();
    loadRules().then(() => { loadTrafficSummary(); loadConnectionsSummary(); });
    loadAlertSettings();
    
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
    // 响应式展示完全交给后置 CSS；不要写内联 display，否则会压过移动端保留表头的规则。
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

// 敏感操作二次认证：当后端返回 403 + reauth_required 时，弹窗要求重新输入密码。
// 成功后刷新 last_reauth，调用方可重试原请求。返回 true 表示已通过、可重试。
async function promptReauth() {
    const pwd = prompt('该操作需要重新验证密码，请输入当前登录密码：');
    if (!pwd) return false;
    const resp = await fetch('/api/reauth', {
        method: 'POST',
        headers: {'Content-Type': 'application/json', 'X-CSRF-Token': csrfToken},
        body: JSON.stringify({password: pwd})
    });
    if (resp.ok) return true;
    let msg = '密码错误';
    try { msg = (await resp.json()).error || msg; } catch (e) {}
    alert(msg);
    return false;
}

// 带 reauth/CSRF 自动重试的 fetch 包装：
// 403+reauth_required → 弹密码框，通过后重试；403+csrf_required（多开标签/页面过夜导致 token 过期）→ 自动刷新 token 重试。
async function fetchWithReauth(url, options) {
    let resp = await fetch(url, options);
    for (let attempt = 0; attempt < 2 && resp.status === 403; attempt++) {
        let body = null;
        try { body = await resp.clone().json(); } catch (e) {}
        if (body && body.csrf_required) {
            await getCsrfToken();
            options.headers['X-CSRF-Token'] = csrfToken;
        } else if (body && body.reauth_required) {
            const ok = await promptReauth();
            if (!ok) break;
        } else {
            break;
        }
        resp = await fetch(url, options);
    }
    return resp;
}

// 通用 POST 请求（自动添加 CSRF Token + reauth 重试）
async function postWithCsrf(url, data) {
    return fetchWithReauth(url, {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
            'X-CSRF-Token': csrfToken
        },
        body: JSON.stringify(data)
    });
}

// 通用 PUT 请求（自动添加 CSRF Token + reauth 重试）
async function putWithCsrf(url, data) {
    return fetchWithReauth(url, {
        method: 'PUT',
        headers: {
            'Content-Type': 'application/json',
            'X-CSRF-Token': csrfToken
        },
        body: JSON.stringify(data)
    });
}

// 通用 DELETE 请求
async function deleteWithCsrf(url) {
    return fetchWithReauth(url, {
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
        <tr data-server-id="${s.id}" class="sortable-server-row">
            <td data-label="排序/编号"><span class="drag-handle server-drag-handle" title="按住三横线拖动服务器" aria-label="拖动服务器排序"><span class="drag-grip-lines" aria-hidden="true"><i></i><i></i><i></i></span></span><span>${esc(s.display_id || s.id)}</span></td>
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
    setupServerSorting();
}

// 通用纵向拖动排序：只允许从专用三横线把手启动，避免手机滚动或轻触卡片时误排序。
function setupPointerSorting(container, itemSelector, handleSelector, onPersist) {
    if (!container || container.dataset.sortReady === '1') return;
    container.dataset.sortReady = '1';
    let active = null;
    const isTouchLikeDevice = window.matchMedia('(max-width: 768px)').matches || navigator.maxTouchPoints > 0;


    const siblingsFor = (state) => [...state.parent.querySelectorAll(`:scope > ${itemSelector}`)].filter(node => node !== state.item && node !== state.placeholder);

    const clearLiftOffsets = (state) => {
        if (!state?.liftedItems?.length) return;
        state.liftedItems.forEach(node => {
            node.style.removeProperty('--sort-shift-y');
            node.style.removeProperty('--sort-shift-scale');
            node.classList.remove('sort-shift-up', 'sort-shift-down', 'sort-lifted');
        });
        state.liftedItems = [];
    };

    const setActive = (state) => {
        if (!state && active) clearLiftOffsets(active);
        active = state;
        container.classList.toggle('drag-sorting', !!state);
        document.body.classList.toggle('dragging-sort-item', !!state);
    };

    const clearDragArtifacts = (state) => {
        if (state?.ghost?.parentNode) state.ghost.parentNode.removeChild(state.ghost);
        if (state?.placeholder?.parentNode) state.placeholder.parentNode.removeChild(state.placeholder);
    };

    const syncGhost = (state, clientX, clientY) => {
        if (!state?.ghost) return;
        const x = clientX - state.offsetX;
        const fingerLift = state.touchLike ? Math.min(state.itemRect.height * 0.34, 54) : 0;
        const y = clientY - state.offsetY - fingerLift;
        const snapOffset = state.snapOffsetY || 0;
        const scaleBoost = state.snapStrength ? (state.scale + state.snapStrength * (state.touchLike ? 0.04 : 0.025)) : state.scale;
        state.ghost.style.transform = `translate3d(${x}px, ${y + snapOffset}px, 0) rotate(${state.rotation}deg) scale(${scaleBoost})`;
    };

    const resolveTarget = (state, clientX, clientY) => {
        if (!state) return null;
        const direct = document.elementFromPoint(clientX, clientY)?.closest(itemSelector);
        if (direct && direct !== state.item && direct.parentElement === state.parent) return direct;
        return siblingsFor(state).find(node => {
            const rect = node.getBoundingClientRect();
            return clientY >= rect.top && clientY <= rect.bottom;
        }) || null;
    };

    const animateReflow = (state) => {
        if (!state?.placeholder) return;
        const placeholderRect = state.placeholder.getBoundingClientRect();
        const siblings = siblingsFor(state);
        clearLiftOffsets(state);
        state.liftedItems = siblings;
        siblings.forEach(node => {
            const rect = node.getBoundingClientRect();
            const goingDown = rect.top >= placeholderRect.top;
            const distanceFactor = Math.min(Math.abs(rect.top - placeholderRect.top) / Math.max(state.itemRect.height, 1), 1.8);
            const shift = goingDown ? state.itemRect.height * (0.18 + distanceFactor * 0.06) : -state.itemRect.height * (0.18 + distanceFactor * 0.06);
            const scale = goingDown ? (0.992 - distanceFactor * 0.01) : (0.994 - distanceFactor * 0.008);
            node.style.setProperty('--sort-shift-y', `${shift}px`);
            node.style.setProperty('--sort-shift-scale', `${Math.max(scale, 0.972)}`);
            node.classList.add('sort-lifted', goingDown ? 'sort-shift-down' : 'sort-shift-up');
        });
        const placeholderCenter = placeholderRect.top + placeholderRect.height / 2;
        const itemCenter = (state.lastClientY ?? state.startY) - state.offsetY + state.itemRect.height / 2;
        const normalizedDelta = (placeholderCenter - itemCenter) / Math.max(state.itemRect.height, 1);
        const snapLimit = state.touchLike ? 16 : 10;
        const snapPull = state.touchLike ? 14 : 10;
        const snapFalloff = state.touchLike ? 1.8 : 1.4;
        state.snapOffsetY = Math.max(Math.min(normalizedDelta * snapPull, snapLimit), -snapLimit);
        state.snapStrength = Math.max(0, 1 - Math.min(Math.abs(normalizedDelta), snapFalloff) / snapFalloff);
        state.placeholder.style.setProperty('--placeholder-pop', `${1 + state.snapStrength * (state.touchLike ? 0.055 : 0.035)}`);
    };

    const buildPlaceholder = (state) => {
        const placeholder = document.createElement(state.item.tagName === 'TR' ? 'tr' : 'div');
        placeholder.className = `${state.item.className} sorting-placeholder`;
        placeholder.style.height = `${state.itemRect.height}px`;
        placeholder.style.width = `${state.itemRect.width}px`;
        if (state.item.tagName === 'TR') {
            const colSpan = state.item.children.length || 1;
            placeholder.innerHTML = `<td colspan="${colSpan}"></td>`;
        }
        return placeholder;
    };

    const buildGhost = (state) => {
        const ghost = state.item.cloneNode(true);
        ghost.classList.remove('sorting-pending');
        ghost.classList.add('sorting-ghost');
        ghost.style.width = `${state.itemRect.width}px`;
        ghost.style.height = `${state.itemRect.height}px`;
        if (state.item.tagName === 'TR') ghost.style.display = 'table';
        document.body.appendChild(ghost);
        return ghost;
    };

    container.addEventListener('pointerdown', (event) => {
        if (container.classList.contains('sorting-disabled') || active) return;
        const item = event.target.closest(itemSelector);
        if (!item || item.parentElement !== container && item.parentElement !== item.closest('.tree-server-rules')) return;
        if (event.button !== undefined && event.button > 0) return;

        const handle = event.target.closest(handleSelector);
        if (!handle) return;

        const rect = item.getBoundingClientRect();
        const pointerOwner = handle;
        setActive({
            item,
            handle: pointerOwner,
            parent: item.parentElement,
            pointerId: event.pointerId,
            startY: event.clientY,
            startX: event.clientX,
            moved: false,
            itemRect: rect,
            offsetX: event.clientX - rect.left,
            offsetY: event.clientY - rect.top,
            ghost: null,
            placeholder: null,
            liftedItems: [],
            snapOffsetY: 0,
            snapStrength: 0,
            lastClientY: event.clientY,
            touchLike: isTouchLikeDevice,
            scale: isTouchLikeDevice ? 1.03 : 1.015,
            rotation: item.matches('.sortable-rule') ? (isTouchLikeDevice ? 0 : (event.clientX % 2 === 0 ? -1.2 : 1.2)) : 0
        });
        pointerOwner.setPointerCapture?.(event.pointerId);
        item.classList.add('sorting-pending');
    });

    container.addEventListener('pointermove', (event) => {
        const state = active;
        if (!state || event.pointerId !== state.pointerId) return;
        state.lastClientY = event.clientY;
        const deltaY = event.clientY - state.startY;
        const deltaX = event.clientX - state.startX;
        if (!state.moved && Math.hypot(deltaX, deltaY) < 8) return;
        if (!state.moved) {
            state.moved = true;
            state.placeholder = buildPlaceholder(state);
            state.parent.insertBefore(state.placeholder, state.item.nextSibling);
            state.ghost = buildGhost(state);
            state.item.classList.remove('sorting-pending');
            state.item.classList.add('sorting-active');
            state.item.style.visibility = 'hidden';
            animateReflow(state);
        }
        event.preventDefault();
        const target = resolveTarget(state, event.clientX, event.clientY);
        if (target && target !== state.placeholder && target.parentElement === state.parent) {
            const box = target.getBoundingClientRect();
            state.parent.insertBefore(state.placeholder, event.clientY < box.top + box.height / 2 ? target : target.nextSibling);
        }
        animateReflow(state);
        syncGhost(state, event.clientX, event.clientY);
    });

    const finish = async (event, cancelled = false) => {
        const state = active;
        if (!state || event.pointerId !== state.pointerId) return;
        setActive(null);
        state.item.classList.remove('sorting-pending', 'sorting-active');
        state.item.style.visibility = '';
        if (state.placeholder?.parentNode) {
            state.placeholder.style.setProperty('--placeholder-pop', '1.06');
            state.parent.insertBefore(state.item, state.placeholder);
        }
        if (state.ghost) {
            state.ghost.style.transition = 'transform .16s cubic-bezier(.22,.61,.36,1), opacity .14s ease, box-shadow .18s ease';
            state.ghost.style.opacity = '.72';
            state.ghost.style.transform = `translate3d(${state.item.getBoundingClientRect().left}px, ${state.item.getBoundingClientRect().top}px, 0) rotate(${state.rotation * 0.4}deg) scale(.985)`;
        }
        await new Promise(resolve => setTimeout(resolve, 120));
        clearDragArtifacts(state);
        if (!cancelled && state.moved) await onPersist(state.parent);
    };
    container.addEventListener('pointerup', event => finish(event));
    container.addEventListener('pointercancel', event => finish(event, true));
}

function setupServerSorting() {
    const tbody = document.querySelector('#serversTable tbody');
    setupPointerSorting(tbody, '.sortable-server-row', '.server-drag-handle', async () => {
        const serverIds = [...tbody.querySelectorAll('.sortable-server-row')].map(row => Number(row.dataset.serverId));
        const resp = await postWithCsrf('/api/servers/reorder', {server_ids: serverIds});
        const data = await resp.json();
        if (!resp.ok || !data.success) {
            showError(data.error || '服务器排序保存失败');
            await loadServers();
            return;
        }
        servers.sort((a, b) => serverIds.indexOf(a.id) - serverIds.indexOf(b.id));
        showSuccess('服务器顺序已保存');
    });
}

function setupRuleSorting() {
    const container = document.getElementById('rulesTree');
    const manualMode = ruleSortKey === 'sort_order' && !ruleFilterText;
    container?.classList.toggle('sorting-disabled', !manualMode);
    if (!manualMode) return;
    setupPointerSorting(container, '.sortable-rule', '.rule-drag-handle', async (list) => {
        const items = [...list.querySelectorAll(':scope > .sortable-rule')];
        const ruleIds = items.map(item => Number(item.dataset.ruleId));
        const serverId = Number(items[0]?.dataset.serverId);
        if (!serverId || !ruleIds.length) return;
        const resp = await postWithCsrf('/api/rules/reorder', {server_id: serverId, rule_ids: ruleIds});
        const data = await resp.json();
        if (!resp.ok || !data.success) {
            showError(data.error || '规则排序保存失败');
            await loadRules();
            return;
        }
        const positions = new Map(ruleIds.map((id, index) => [id, index]));
        rules.forEach(rule => { if (positions.has(rule.id)) rule.sort_order = positions.get(rule.id); });
        showSuccess('规则顺序已保存；规则编号未改变');
    });
}

// 检查服务器状态
async function checkServer(id) {
    const resp = await postWithCsrf(`/api/servers/${id}/check`, {});
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
    if (!container) return;
    const list = getFilteredSortedRules();

    // 更新“总活跃连接”汇总（此前该文案是写死的摆设，这里改为真实数据）
    const connEl = document.getElementById('connectionsSummaryText');
    if (connEl) {
        const total = rules.reduce((s, r) => s + (r.enabled ? (r.active_connections ?? 0) : 0), 0);
        connEl.textContent = `总活跃连接：${total}`;
    }

    if (!list.length) {
        container.innerHTML = `<div style="text-align:center;color:#6b7280;padding:24px 0;">${rules.length ? '没有匹配当前搜索条件的规则' : '暂无转发规则，点击上方“+ 添加规则”创建'}</div>`;
        return;
    }

    // 按服务器分组
    const groups = {};
    list.forEach(r => {
        const sn = r.server_name || '未知服务器';
        if (!groups[sn]) groups[sn] = [];
        groups[sn].push(r);
    });
    const serverNames = Object.keys(groups); // API 已按服务器手动顺序返回，保留首次出现顺序。
    const filtering = !!ruleFilterText; // 搜索时强制展开所有分组，避免结果被折叠遮住

    container.innerHTML = serverNames.map(sn => {
        const serverRules = groups[sn];
        const collapsed = !filtering && collapsedTreeGroups.has(sn);
        const groupAllSelected = serverRules.every(r => selectedRuleIds.has(r.id));
        return `
            <div class="tree-server">
                <div class="tree-server-header ${collapsed ? '' : 'expanded'}" data-act="toggleTreeGroup" data-arg="${esc(sn)}">
                    <input type="checkbox" data-change="toggleTreeGroupSelection" data-arg="${esc(sn)}" ${groupAllSelected ? 'checked' : ''} title="全选该服务器下的规则" style="width:16px;height:16px;margin-right:6px;">
                    <span class="tree-server-icon">✿</span>
                    <span class="tree-server-name">${esc(sn)}</span>
                    <span class="tree-server-count">${serverRules.length} 条规则</span>
                    <span class="tree-arrow">${collapsed ? '▶' : '▼'}</span>
                </div>
                <div class="tree-server-rules ${collapsed ? '' : 'expanded'}" id="tree-${esc(sn.replace(/'/g, "_"))}" style="${collapsed ? 'display:none' : ''}">
                    ${serverRules.map((r, idx) => renderTreeRule(r, idx)).join('')}
                </div>
            </div>
        `;
    }).join('');
    setupRuleSorting();
}

function renderTreeRule(r, idx) {
    const limitGB = r.traffic_limit_gb || 0;
    const traffic = getTrafficDisplay(r.traffic_used_bytes, limitGB);
    const targetDisplay = (r.target_host && r.target_host !== r.target_ip) ? `${r.target_host} (${r.target_ip})` : r.target_ip;
    const connCount = r.active_connections ?? 0;
    const connClass = connCount >= 50 ? 'conn-full' : connCount >= 20 ? 'conn-high' : '';
    const overLimit = limitGB > 0 && Number(r.traffic_used_bytes || 0) >= limitGB * 1024 ** 3;

    const BORDER_COLORS = ['#667eea','#f59e0b','#10b981','#ec4899','#3b82f6','#8b5cf6','#ef4444','#06b6d4'];
    const borderColor = BORDER_COLORS[idx % BORDER_COLORS.length];

    const statusBadges = [];
    statusBadges.push(`<span class="tree-rule-status ${r.enabled ? 'enabled' : 'disabled'}">${r.enabled ? '启用中' : '已停用'}</span>`);
    if (r.status === 'desynced') statusBadges.push('<span class="tree-rule-status warning">待补下发</span>');
    else if (r.status === 'unknown') statusBadges.push('<span class="tree-rule-status danger">远端未知</span>');
    else if (overLimit && !r.enabled) statusBadges.push('<span class="tree-rule-status warning">超限停用</span>');
    else if (r.enabled) statusBadges.push('<span class="tree-rule-status synced">已下发</span>');
    else statusBadges.push('<span class="tree-rule-status muted">本地停用</span>');

    const statusSummary = r.status === 'desynced'
        ? '待补下发'
        : r.status === 'unknown'
            ? '远端状态未知'
            : overLimit && !r.enabled
                ? '超限后已停用'
                : r.enabled
                    ? 'Agent 已下发'
                    : '本地已停用';

    return `
        <div class="tree-rule sortable-rule" data-rule-id="${r.id}" data-server-id="${r.server_id}" style="border-left-color:${borderColor}">
            <div class="tree-rule-main">
                <div class="tree-rule-controls">
                    <span class="drag-handle rule-drag-handle" title="按住三横线拖动规则；规则编号不会改变" aria-label="拖动规则排序"><span class="drag-grip-lines" aria-hidden="true"><i></i><i></i><i></i></span></span>
                    <input type="checkbox" data-change="toggleRuleSelection" data-arg="${r.id}" ${selectedRuleIds.has(r.id) ? 'checked' : ''} title="选择该规则参与批量操作" aria-label="选择规则 #${r.id}">
                    <span class="tree-rule-id" title="TGBOT 删除命令使用的规则序号">#${r.id}</span>
                </div>
                <div class="tree-rule-route">
                    <span class="tree-rule-route-label">转发路径</span>
                    <div class="tree-rule-route-value">
                        <span class="tree-rule-port">${r.local_port}</span>
                        <span class="tree-rule-arrow">→</span>
                        <span class="tree-rule-target">${esc(targetDisplay)}:${r.target_port}</span>
                    </div>
                </div>
                <span class="tree-rule-status-group">${statusBadges.join('')}</span>
            </div>
            <div class="tree-rule-info">
                <span class="tree-rule-info-item"><small>同步状态</small><strong class="tree-rule-status-text">${statusSummary}</strong></span>
                <span class="tree-rule-info-item"><small>活跃连接</small><strong class="${connClass}">${connCount}</strong></span>
                ${r.created_at ? `<span class="tree-rule-info-item"><small>创建时间</small><strong>${esc(formatCreatedAt(r.created_at))}</strong></span>` : ''}
                <span class="tree-rule-info-item tree-rule-remark ${r.created_at ? '' : 'is-wide'}"><small>规则备注</small><strong>${esc(r.remark || '未填写')}</strong></span>
            </div>
            <div class="tree-rule-traffic-wrap" title="${traffic.unlimited ? `已使用 ${traffic.usedGB} GB（未设置限额）` : `已使用 ${traffic.percent.toFixed(1)}%`}">
                <div class="tree-rule-traffic-meta"><span>流量进度</span><strong>${traffic.summaryText}</strong></div>
                <div class="tree-rule-traffic-bar ${traffic.unlimited ? 'is-unlimited' : ''}">
                    <div class="tree-rule-traffic-fill ${traffic.barClass}" style="--rule-progress:${traffic.unlimited ? 100 : traffic.percent}%;--rule-color:${borderColor};"></div>
                </div>
            </div>
            <div class="tree-rule-actions">
                <button data-act="toggleRule" data-arg="${r.id}">${r.enabled ? '禁用' : '启用'}</button>
                <button data-act="editRule" data-arg="${r.id}">编辑</button>
                <button data-act="deleteRule" data-arg="${r.id}">删除</button>
            </div>
        </div>
    `;
}

// 分组折叠状态：跨重渲染保留（连接数每 30s 刷新一次会整体重绘）
const collapsedTreeGroups = new Set();

function toggleTreeGroup(serverName) {
    if (collapsedTreeGroups.has(serverName)) collapsedTreeGroups.delete(serverName);
    else collapsedTreeGroups.add(serverName);
    renderRulesTree();
}

// 勾选/取消整个服务器分组下的所有规则
function toggleTreeGroupSelection(serverName, checked) {
    rules.filter(r => (r.server_name || '未知服务器') === serverName)
         .forEach(r => { if (checked) selectedRuleIds.add(r.id); else selectedRuleIds.delete(r.id); });
    updateBulkBar();
    renderRulesTree();
}

function getFilteredSortedRules() {
    let items = [...rules];
    if (ruleFilterText) {
        const q = ruleFilterText.toLowerCase();
        items = items.filter(r => [r.server_name, r.local_port, r.target_host, r.target_ip, r.target_port, r.remark].join(' ').toLowerCase().includes(q));
    }
    items.sort((a, b) => {
        if (ruleSortKey === 'sort_order') {
            const serverOrder = Number(a.server_sort_order ?? 0) - Number(b.server_sort_order ?? 0);
            if (serverOrder !== 0) return serverOrder;
            const manualOrder = Number(a.sort_order ?? 0) - Number(b.sort_order ?? 0);
            if (manualOrder !== 0) return manualOrder;
            return Number(b.id || 0) - Number(a.id || 0);
        }
        const av = a[ruleSortKey] ?? '';
        const bv = b[ruleSortKey] ?? '';

        return ruleSortDir === 'asc' ? (av > bv ? 1 : -1) : (av < bv ? 1 : -1);
    });
    return items;
}

// 排序：由规则区的下拉框驱动，值形如 "created_at:desc"
function setRuleSort(key, dir) {
    if (dir) { ruleSortKey = key; ruleSortDir = dir; }
    else if (ruleSortKey === key) ruleSortDir = ruleSortDir === 'asc' ? 'desc' : 'asc';
    else { ruleSortKey = key; ruleSortDir = 'asc'; }
    renderRulesTree();
}

// 搜索：由规则区的搜索框驱动（此前函数存在但页面上没有任何入口，属于摆设，现已接通）
function setRuleFilter(value) {
    ruleFilterText = (value || '').trim();
    renderRulesTree();
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
    return `${y}-${m}-${day} ${hh}:${mm}:${ss}`;
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

document.addEventListener('keydown', (e) => {
    if (e.key !== 'Escape') return;
    const openModal = [...document.querySelectorAll('.modal')].find(m => m.style.display === 'block');
    if (openModal?.id) closeModal(openModal.id);
});

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
    
    const resp = editId ? await putWithCsrf(`/api/servers/${editId}`, data) : await postWithCsrf('/api/servers', data);
    
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
    if (!confirm('确定删除此服务器？删除前会先清理远端规则。')) return;
    let resp = await deleteWithCsrf(`/api/servers/${id}`);
    let data = {}; try { data = await resp.json(); } catch (_) {}
    if (resp.status === 409 && data.require_force) {
        const detail = (data.cleanup_failed || []).map(x => `端口 ${x.local_port}: ${x.error}`).join('\n');
        if (!confirm(`远端规则未确认清理：\n${detail}\n\n仍要强制删除面板记录吗？`)) return;
        resp = await deleteWithCsrf(`/api/servers/${id}?force=1`);
        try { data = await resp.json(); } catch (_) { data = {}; }
    }
    if (!resp.ok) { showError(data.error || '删除失败'); return; }
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
    toast.style.cssText = `position:fixed;top:20px;right:20px;background:${color};color:#172033;padding:14px 16px;border-radius:10px;box-shadow:0 4px 12px rgba(0,0,0,0.25);z-index:10000;max-width:420px;display:flex;gap:10px;align-items:flex-start;font-weight:700`;
    toast.innerHTML = `<div style="font-size:18px">${color === '#f5576c' ? '❌' : color === '#ffa500' ? '⚠️' : '✅'}</div><div style="flex:1"><div>${esc(message)}</div>${detail ? `<div style="margin-top:6px;font-size:12px;opacity:.9">${esc(detail)}</div>` : ''}</div><button style="background:#fbcfe8;border:1px solid rgba(23,32,51,.16);color:#172033;font-size:18px;cursor:pointer">×</button>`;
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
    document.getElementById('editRuleNewId').value = rule.id;
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
    const newId = parseInt(document.getElementById('editRuleNewId').value);
    if (newId && newId !== parseInt(id)) data.new_id = newId;
    
    const resp = await putWithCsrf(`/api/rules/${id}`, data);
    
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

// 整理规则编号为连续的 ①②③…（只改面板编号，不动 Agent/iptables）
async function renumberRules() {
    if (!confirm('确定整理规则编号吗？\n当前规则会按编号从小到大重排为 ①②③…，转发不会中断。')) return;
    const resp = await postWithCsrf('/api/rules/renumber', {});
    const data = await resp.json().catch(() => ({}));
    if (resp.ok && data.success) {
        await loadRules();
        showSuccess(data.changed ? `已整理 ${data.changed} 条规则编号` : '编号已经连续，无需整理');
    } else {
        showError('整理失败', '#f5576c', 5000, data.error || '未知错误');
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

// 登出（POST + CSRF，避免跨站 GET 强制登出）
async function logout() {
    if (!confirm('确定要登出吗？')) return;
    const resp = await postWithCsrf('/logout', {});
    if (resp.ok || resp.redirected) window.location.href = '/login';
    else showError('登出失败');
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
        const logoutResp = await postWithCsrf('/logout', {});
        if (!logoutResp.ok && !logoutResp.redirected) showError('密码已修改，但自动登出失败，请手动重新登录');
        window.location.href = '/login';
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
    await loadAlertSettings();
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
    }
    
    if (alerts.length > 0) {
        showAlert(alerts.join('\n'));
    }
}

// 显示告警
let alertBoxTimer = null;
function showAlert(message) {
    let div = document.getElementById('alertBox');
    if (!div) {
        div = document.createElement('div');
        div.id = 'alertBox';
        div.style.cssText = 'position:fixed;top:20px;right:20px;background:#ffa500;color:#000;padding:15px 20px;border-radius:8px;box-shadow:0 4px 12px rgba(0,0,0,0.3);max-width:400px;z-index:10000';
        document.body.appendChild(div);
    }
    // 复用同一个提示框并刷新内容/倒计时（此前若 10s 内已有提示框，新消息会被静默丢弃）
    div.innerHTML = `<strong>⚠ 告警</strong><br>${esc(message).replace(/\n/g, '<br>')}`;
    if (alertBoxTimer) clearTimeout(alertBoxTimer);
    alertBoxTimer = setTimeout(() => { div.remove(); alertBoxTimer = null; }, 10000);
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
    renderRulesTree();
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
        await loadServers();
    }
}

async function loadTrafficSummary() {
    const resp = await fetch('/api/traffic/summary');
    const data = await resp.json();
    const el = document.getElementById('trafficSummary');
    if (!el) return;
    if (!data.success) { el.innerHTML = '流量汇总加载失败'; return; }

    const totalGB = (data.total_bytes / (1024**3)).toFixed(2);
    // 标签统一为“服务器:备注”；没有备注时回退到端口，确保每条规则可区分。
    const labels = data.top_rules.map(r => {
        const name = String(r.server_name || '未知节点');
        const remark = String(r.remark || '').trim() || String(r.local_port || '未备注');
        return `${name}:${remark}`;
    });
    const values = data.top_rules.map(r => Number((r.traffic_used_bytes / (1024**3)).toFixed(2)));

    el.innerHTML = `<div style="display:grid;gap:8px;color:#1f2937;font-weight:700;min-width:0"><div>总流量：<b style="color:#111827">${totalGB} GB</b></div><div>规则数：<b style="color:#111827">${data.rules_count}</b>，启用：<b style="color:#111827">${data.enabled_count}</b></div><canvas id="trafficChart" height="170" aria-label="Top 10 节点流量横向条形图"></canvas></div>`;

    const canvas = document.getElementById('trafficChart');
    if (!(canvas && labels.length)) return;

    const ctx = canvas.getContext('2d');
    const isMobile = window.innerWidth <= 768;
    const parentW = canvas.parentElement.clientWidth;
    const w = canvas.width = Math.max(240, Math.floor(parentW));
    const rowH = isMobile ? 31 : 29;
    const h = canvas.height = Math.max(70, labels.length * rowH + 22);

    ctx.clearRect(0, 0, w, h);

    const max = Math.max(...values, 1);
    const plotR = 8;
    const labelLeft = 6;
    const labelGap = 8;
    const labelW = Math.min(isMobile ? 128 : 220, Math.max(78, Math.floor(w * (isMobile ? 0.40 : 0.34))));
    const barX = labelLeft + labelW + labelGap;
    const barMaxW = Math.max(60, w - barX - plotR);

    const fitLabel = (text, maxWidth) => {
        if (ctx.measureText(text).width <= maxWidth) return text;
        const suffix = '…';
        let lo = 0, hi = text.length;
        while (lo < hi) {
            const mid = Math.ceil((lo + hi) / 2);
            if (ctx.measureText(text.slice(0, mid) + suffix).width <= maxWidth) lo = mid;
            else hi = mid - 1;
        }
        return text.slice(0, lo) + suffix;
    };

    ctx.textBaseline = 'alphabetic';
    ctx.lineWidth = 1;

    values.forEach((v, i) => {
        const y = 10 + i * rowH;
        const barH = isMobile ? 15 : 14;
        const bw = Math.max(4, (v / max) * barMaxW);

        ctx.font = isMobile ? '600 11px sans-serif' : '600 12px sans-serif';
        ctx.fillStyle = '#1f2937';
        ctx.textAlign = 'right';
        ctx.textBaseline = 'middle';
        ctx.fillText(fitLabel(labels[i] || '', labelW), labelLeft + labelW, y + barH / 2);

        ctx.fillStyle = '#e5e7eb';
        ctx.fillRect(barX, y, barMaxW, barH);
        ctx.fillStyle = '#667eea';
        ctx.fillRect(barX, y, bw, barH);

        const valueText = `${v}G`;
        ctx.font = isMobile ? '700 10px sans-serif' : '700 11px sans-serif';
        const valueW = ctx.measureText(valueText).width;
        ctx.textAlign = 'left';
        ctx.fillStyle = '#111827';
        ctx.fillText(valueText, Math.min(barX + bw + 4, w - valueW - 2), y + barH / 2);
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
    // 服务器导出默认不含 token（后端脱敏）。如需含 token，走单独入口并要求二次验证密码。
    if (type === 'servers') {
        const withTokens = confirm('导出服务器列表。\n\n点“确定”导出【含 token】（敏感，需重新验证密码并会记入审计日志）；\n点“取消”导出【不含 token】（推荐）。');
        if (withTokens) {
            const ok = await promptReauth();
            if (!ok) return;
            window.open(`/api/export/${type}?include_tokens=1`, '_blank');
            return;
        }
    }
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
    const cmd = document.getElementById('tgCommandEnabled');
    const daily = document.getElementById('tgDailySummaryEnabled');
    const dailyTime = document.getElementById('tgDailySummaryTime');
    const audit = document.getElementById('tgAuditEnabled');
    const limit = document.getElementById('tgLimitAlertsEnabled');
    if (cmd) cmd.checked = !!data.command_enabled;
    if (daily) daily.checked = !!data.daily_summary_enabled;
    if (dailyTime) dailyTime.value = data.daily_summary_time || '09:00';
    if (audit) audit.checked = !!data.audit_enabled;
    if (limit) limit.checked = !!data.limit_alerts_enabled;
}

async function saveAlertSettings() {
    const tg_bot_token = document.getElementById('tgBotToken').value;
    const tg_chat_id = document.getElementById('tgChatId').value;
    const offline_seconds = parseInt(document.getElementById('alertOfflineSeconds').value || '300');
    const command_enabled = !!document.getElementById('tgCommandEnabled')?.checked;
    const daily_summary_enabled = !!document.getElementById('tgDailySummaryEnabled')?.checked;
    const daily_summary_time = document.getElementById('tgDailySummaryTime')?.value || '09:00';
    const audit_enabled = !!document.getElementById('tgAuditEnabled')?.checked;
    const limit_alerts_enabled = !!document.getElementById('tgLimitAlertsEnabled')?.checked;
    const resp = await postWithCsrf('/api/settings/alerts', {
        tg_bot_token,
        tg_chat_id,
        offline_seconds,
        command_enabled,
        daily_summary_enabled,
        daily_summary_time,
        audit_enabled,
        limit_alerts_enabled,
    });
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
    const el = document.getElementById('reconcileResult');
    if (!data.success) {
        if (el) el.innerHTML = `<div class="reconcile-item error">❌ ${esc(data.error || '检查失败')}</div>`;
        showError(data.error || '检查失败');
        return;
    }

    const statusMeta = {
        ok: {icon: '✅', label: '已下发', className: 'ok'},
        reapplied: {icon: '🛠️', label: '远端缺失，已补下发', className: 'warning'},
        failed: {icon: '❌', label: '补下发失败', className: 'error'},
        error: {icon: '❌', label: '检查异常', className: 'error'},
        remote_suspended: {icon: '⛔', label: '远端已挂起，已同步停用', className: 'warning'},
        over_limit_skipped: {icon: '⚠️', label: '超限规则，未重新下发', className: 'warning'},
    };

    if (el) {
        el.innerHTML = (data.results || []).map(item => {
            const meta = statusMeta[item.status] || {icon: 'ℹ️', label: item.status || '未知状态', className: 'muted'};
            const extra = item.error ? `：${esc(item.error)}` : item.http ? `：HTTP ${item.http}` : '';
            return `<div class="reconcile-item ${meta.className}"><span class="reconcile-rule-id">#${item.rule_id ?? '?'}</span><span class="reconcile-status">${meta.icon} ${meta.label}${extra}</span></div>`;
        }).join('') || '<div class="reconcile-item muted">暂无检查结果</div>';
    }

    const repaired = (data.results || []).filter(x => x.status === 'reapplied').length;
    const failed = (data.results || []).filter(x => x.status === 'failed' || x.status === 'error').length;
    showSuccess(`一致性检查完成：共 ${data.results.length} 条，补下发 ${repaired} 条，异常 ${failed} 条`);
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
        // 刷新树形视图：每条规则卡片上的“连接”与标题里的“总活跃连接”都会更新。
        // （此前这里调用的 renderRules() 依赖不存在的 #rulesTable，抛错后被 catch 吞掉，
        //   造成连接数在页面上永远显示 0 —— 属于典型“摆件”，现已修复。）
        renderRulesTree();
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
    renumberRules: () => renumberRules(),
    // 带字符串参数
    bulkAction: (el) => bulkAction(el.dataset.arg),
    importJson: (el) => importJson(el.dataset.arg),
    exportData: (el) => exportData(el.dataset.arg),
    closeModal: (el) => closeModal(el.dataset.arg),
    closeModalSelf: (el) => { const m = el.closest('.modal'); if (m) m.remove(); },
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
    } else if (el.dataset.change === 'toggleTreeGroupSelection') {
        toggleTreeGroupSelection(el.dataset.arg, el.checked);
    } else if (el.dataset.change === 'toggleAllRules') {
        toggleAllRules(el.checked);
    } else if (el.dataset.change === 'setRuleSortSelect') {
        const [key, dir] = (el.value || 'created_at:desc').split(':');
        setRuleSort(key, dir === 'asc' ? 'asc' : 'desc');
    } else if (el.dataset.change === 'saveForceHttpsTop') {
        saveForceHttpsTop(el.checked);
    }
});

// 搜索框：input 事件实时过滤（同样走事件委托，兼容无 'unsafe-inline' 的 CSP）
document.addEventListener('input', (e) => {
    const el = e.target.closest('[data-input]');
    if (!el) return;
    if (el.dataset.input === 'setRuleFilter') setRuleFilter(el.value);
});

document.addEventListener('submit', (e) => {
    const el = e.target.closest('[data-submit]');
    if (!el) return;
    e.preventDefault();
    if (el.dataset.submit === 'addServer') addServer();
    else if (el.dataset.submit === 'addRule') addRule();
});
