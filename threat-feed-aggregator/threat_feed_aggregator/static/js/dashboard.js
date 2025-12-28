/**
 * Dashboard Logic for Threat Feed Aggregator
 * Relies on window.AppConfig for server-side variables.
 */

document.addEventListener('DOMContentLoaded', function() {
    updateLogs();
    updateHistory();
    updateSourceStats();
    initMap();
    setInterval(updateLogs, 3000); 
    setInterval(updateHistory, 10000);
    setInterval(updateSourceStats, 10000);

    // Handle Flash Messages
    if (window.AppConfig && window.AppConfig.flashMessages) {
        window.AppConfig.flashMessages.forEach(msg => {
            const icon = (msg.category === 'danger') ? 'error' : msg.category;
            Swal.fire({
                title: msg.category.charAt(0).toUpperCase() + msg.category.slice(1),
                text: msg.message,
                icon: icon,
                timer: 3000,
                showConfirmButton: false,
                toast: true,
                position: 'top-end'
            });
        });
    }
});

function updateSourceStats() {
    fetch('/api/source_stats')
        .then(r => r.json())
        .then(data => {
            const sources = data.sources || {};
            const totals = data.totals || {};

            // 1. Update Top Cards
            if (totals.total !== undefined) document.getElementById('stat-total').textContent = totals.total;
            if (totals.ip !== undefined) document.getElementById('stat-ip').textContent = totals.ip;
            if (totals.domain !== undefined) document.getElementById('stat-domain').textContent = totals.domain;
            if (totals.feeds !== undefined) document.getElementById('stat-feeds').textContent = totals.feeds;

            // 2. Update Source Table
            for (const sourceName in sources) {
                const stat = sources[sourceName];
                if (typeof stat !== 'object') continue;

                const rows = document.querySelectorAll('tr');
                rows.forEach(row => {
                    const nameEl = row.querySelector('strong');
                    if (nameEl && nameEl.textContent === sourceName) {
                        const badge = row.querySelector('.badge');
                        if (badge) badge.textContent = stat.count || 0;

                        const cells = row.querySelectorAll('td');
                        if (cells.length >= 3) {
                            cells[2].textContent = stat.last_updated || 'N/A';
                        }
                    }
                });
            }
        });
}

function runAggregator() {
    Swal.fire({
        title: 'Triggering Aggregator', text: 'Process started in background...',
        icon: 'info', timer: 2000, timerProgressBar: true, showConfirmButton: false,
        didOpen: () => { Swal.showLoading(); }
    });
    fetch('/run').then(() => {
        // Poll more frequently for a short while
        let count = 0;
        const interval = setInterval(() => {
            updateHistory(); 
            updateSourceStats();
            if (++count > 10) clearInterval(interval);
        }, 2000);
    });
}

function getCsrfToken() {
    const meta = document.querySelector('meta[name="csrf-token"]');
    return meta ? meta.content : (AppConfig ? AppConfig.csrfToken : '');
}

function updateHistory() {
    fetch('/api/history?limit=6')
        .then(r => {
            if (!r.ok) throw new Error(`History fetch failed: ${r.status}`);
            return r.json();
        })
        .then(data => {
            const tbody = document.getElementById('historyTableBody');
            if (!tbody) return;
            
            if (!Array.isArray(data) || data.length === 0) { 
                tbody.innerHTML = '<tr><td colspan="5" class="text-center py-3">No records.</td></tr>'; 
                return; 
            }
            
            let newHtml = '';
            data.forEach(item => {
                const statusClass = item.status === 'success' ? 'bg-success' : (item.status === 'running' ? 'bg-info' : 'bg-danger');
                newHtml += `<tr><td class="ps-4 text-muted small">${item.start_time}</td><td class="fw-bold">${item.source_name}</td><td><span class="badge ${statusClass}">${item.status.toUpperCase()}</span></td><td>${item.items_processed || 0}</td><td class="text-end pe-4 small text-muted">${item.message || '-'}</td></tr>`;
            });
            tbody.innerHTML = newHtml;
        })
        .catch(err => console.error('Update history failed:', err));
}

function viewAllHistory() {
    fetch('/api/history?limit=100')
        .then(r => r.json())
        .then(data => {
            const tbody = document.getElementById('fullHistoryTableBody');
            if (!tbody) return;
            
            let newHtml = '';
            data.forEach(item => {
                const statusClass = item.status === 'success' ? 'bg-success' : (item.status === 'running' ? 'bg-info' : 'bg-danger');
                newHtml += `<tr><td class="ps-4 text-muted small">${item.start_time}</td><td class="fw-bold">${item.source_name}</td><td><span class="badge ${statusClass}">${item.status.toUpperCase()}</span></td><td>${item.items_processed || 0}</td><td class="text-end pe-4 small text-muted">${item.message || '-'}</td></tr>`;
            });
            tbody.innerHTML = newHtml;
            
            // Show the modal
            const historyModal = new bootstrap.Modal(document.getElementById('historyModal'));
            historyModal.show();
        })
        .catch(err => Swal.fire('Error', 'Failed to load full history', 'error'));
}

function updateLogs() {
    const hidePollsEl = document.getElementById('hidePolls');
    const hidePolls = hidePollsEl ? hidePollsEl.checked : true;
    
    fetch('/api/live_logs')
        .then(r => {
            if (!r.ok) throw new Error(`Logs fetch failed: ${r.status}`);
            return r.json();
        })
        .then(data => {
            const logWindow = document.getElementById('logWindow');
            if (!logWindow) return;
            const wasAtBottom = logWindow.scrollHeight - logWindow.clientHeight <= logWindow.scrollTop + 50;
            
            if (data.length === 0) {
                logWindow.innerHTML = '<div class="text-muted italic">Waiting for logs...</div>';
                return;
            }

            logWindow.textContent = '';
            data.forEach(line => {
                if (hidePolls && (line.includes('GET /api/') || line.includes('GET /status'))) return;
                const div = document.createElement('div'); div.className = 'log-line mb-1'; div.textContent = line;
                if (line.includes('ERROR')) div.style.color = '#f87171'; else if (line.includes('WARNING')) div.style.color = '#fbbf24'; else if (line.includes('SUCCESS') || line.includes('Completed') || line.includes('Written batch')) div.style.color = '#4ade80';
                logWindow.appendChild(div);
            });
            if (wasAtBottom) logWindow.scrollTop = logWindow.scrollHeight;
        })
        .catch(err => console.error('Update logs failed:', err));
}

function clearTerminal() { 
    const logWindow = document.getElementById('logWindow');
    if (logWindow) logWindow.textContent = ''; 
}

function clearHistory() { 
    if(confirm('Clear history?')) {
        fetch('/api/history/clear', { 
            method: 'POST', 
            headers: { 
                'X-CSRFToken': getCsrfToken(),
                'Content-Type': 'application/json'
            } 
        })
        .then(r => {
            if (!r.ok) return r.text().then(text => { throw new Error(text || `Server error ${r.status}`) });
            return r.json();
        })
        .then(data => {
            if (data.status === 'success') {
                Swal.fire('Cleared!', data.message, 'success');
                updateHistory();
            } else {
                Swal.fire('Error', data.message || 'Failed to clear history', 'error');
            }
        })
        .catch(err => {
            console.error('Clear history error:', err);
            Swal.fire('Error', `Network error: ${err.message}`, 'error');
        });
    }
}

function updateMS365() { 
    Swal.fire({title:'Updating MS365...', didOpen:()=>{Swal.showLoading();}}); 
    fetch('/api/update_ms365', {
        method:'POST', 
        headers:{'X-CSRFToken': getCsrfToken()}
    }).then(r=>r.json()).then(d=> {
        Swal.fire('Result', d.message, d.status);
        updateHistory();
        updateSourceStats();
    }); 
}

function updateGitHub() { 
    Swal.fire({title:'Updating GitHub...', didOpen:()=>{Swal.showLoading();}}); 
    fetch('/api/update_github', {
        method:'POST', 
        headers:{'X-CSRFToken': getCsrfToken()}
    }).then(r=>r.json()).then(d=> {
        Swal.fire('Result', d.message, d.status);
        updateHistory();
        updateSourceStats();
    }); 
}

function updateAzure() { 
    Swal.fire({title:'Updating Azure...', didOpen:()=>{Swal.showLoading();}}); 
    fetch('/api/update_azure', {
        method:'POST', 
        headers:{'X-CSRFToken': getCsrfToken()}
    }).then(r=>r.json()).then(d=> {
        Swal.fire('Result', d.message, d.status);
        updateHistory();
        updateSourceStats();
    }); 
}

function runSingleSource(name) { 
    Swal.fire({title:`Triggering ${name}...`, icon:'info', timer:1500, showConfirmButton:false, didOpen:()=>{Swal.showLoading();}}); 
    fetch('/run').then(() => {
        setTimeout(() => {
            updateHistory(); 
            updateSourceStats();
        }, 1500);
    }); 
}

function showAddSourceModal() {
    Swal.fire({
        title: 'Add Threat Source',
        html: `<div class="text-start mb-3"><label class="small fw-bold">Name</label><input type="text" id="srcName" class="form-control"></div><div class="text-start mb-3"><label class="small fw-bold">URL</label><input type="text" id="srcUrl" class="form-control"></div><div class="row"><div class="col-6"><label class="small fw-bold">Format</label><select id="srcFormat" class="form-select"><option value="text">Text</option><option value="json">JSON</option><option value="csv">CSV</option></select></div><div class="col-6"><label class="small fw-bold">Interval</label><input type="number" id="srcInterval" class="form-control" value="60"></div></div>`,
        confirmButtonText: 'Add', showCancelButton: true,
        preConfirm: () => { 
            const name = document.getElementById('srcName').value; const url = document.getElementById('srcUrl').value;
            if (!name || !url) Swal.showValidationMessage('Required');
            return { name, url, format: document.getElementById('srcFormat').value, schedule_interval_minutes: document.getElementById('srcInterval').value };
        }
    }).then(result => { if (result.isConfirmed) submitForm(AppConfig.urls.addSource, result.value); });
}

function showEditSourceModal(index, source) {
    Swal.fire({
        title: `Edit Source: ${source.name}`,
        html: `<div class="text-start mb-2"><label class="small fw-bold">Name</label><input type="text" id="eName" class="form-control" value="${source.name}"></div><div class="text-start mb-2"><label class="small fw-bold">URL</label><input type="text" id="eUrl" class="form-control" value="${source.url}"></div><div class="row g-2 mb-2"><div class="col-6"><label class="small fw-bold">Format</label><select id="eFormat" class="form-select"><option value="text" ${source.format==='text'?'selected':''}>Text</option><option value="json" ${source.format==='json'?'selected':''}>JSON</option><option value="csv" ${source.format==='csv'?'selected':''}>CSV</option></select></div><div class="col-6"><label class="small fw-bold">Interval</label><input type="number" id="eInterval" class="form-control" value="${source.schedule_interval_minutes}"></div></div><div class="text-start"><label class="small fw-bold">Confidence (0-100)</label><input type="number" id="eConf" class="form-control" value="${source.confidence || 50}"></div>`,
        showCancelButton: true, confirmButtonText: 'Save Changes',
        preConfirm: () => { const name = document.getElementById('eName').value; const url = document.getElementById('eUrl').value; if (!name || !url) Swal.showValidationMessage(`Required`); return { name, url, format: document.getElementById('eFormat').value, schedule_interval_minutes: document.getElementById('eInterval').value, confidence: document.getElementById('eConf').value }; }
    }).then(res => { if (res.isConfirmed) submitForm(`/system/update_source/${index}`, res.value); });
}

function testSource(name) { 
    Swal.fire({ title: 'Testing Feed...', allowOutsideClick: false, didOpen: () => { Swal.showLoading(); } });
    const sources = AppConfig.sourceUrls; 
    const source = sources.find(s => s.name === name);
    if (!source) { Swal.fire('Error', 'Not found', 'error'); return; }
    fetch('/api/test_feed', { 
        method: 'POST', 
        headers: { 
            'Content-Type': 'application/json', 
            'X-CSRFToken': getCsrfToken() 
        }, 
        body: JSON.stringify(source) 
    })
    .then(r => r.json()).then(data => {
        if (data.status === 'success') {
            Swal.fire({ title: 'Test OK!', html: `<div class="text-start text-success fw-bold">${data.message}</div><hr><small>Sample:</small><ul class="small"><li>${data.sample.join('</li><li>')}</li></ul>`, icon: 'success' });
            updateHistory();
            updateSourceStats();
        }
        else Swal.fire('Failed', data.message, 'error');
    });
}

function showAddWhitelistModal() {
    Swal.fire({ title: 'Add to Safe List', input: 'text', showCancelButton: true, confirmButtonText: 'Add' }).then(result => {
        if (result.isConfirmed) submitForm(AppConfig.urls.addWhitelist, { item: result.value, description: 'Added from Dashboard' });
    });
}

function initMap() {
    const data = AppConfig.countryStats;
    try { 
        if (typeof jsVectorMap !== 'undefined') { 
            const map = new jsVectorMap({ 
                selector: '#world-map', 
                map: 'world', 
                zoomOnScroll: false, 
                zoomButtons: true,
                visualizeData: { scale: ['#e2e8f0', '#4f46e5'], values: data }, 
                onRegionTooltipShow(event, tooltip, code) { 
                    tooltip.text(`<div class="p-2"><h6 class="mb-1">${tooltip.text()}</h6><span class="badge bg-primary">${data[code] || 0} Indicators</span></div>`, { isHtml: true }); 
                } 
            });

            const mapEl = document.getElementById('world-map');
            if (mapEl) {
                mapEl.addEventListener('wheel', function(e) {
                    if (e.ctrlKey) {
                        e.preventDefault();
                        if (e.deltaY < 0) map.setScale(map.scale * 1.2, e.offsetX, e.offsetY);
                        else map.setScale(map.scale / 1.2, e.offsetX, e.offsetY);
                    }
                }, { passive: false });
            }
        } 
    } catch(e) { console.error(e); }
}

function submitForm(action, data) {
    const form = document.createElement('form'); form.method = 'POST'; form.action = action;
    for (const key in data) { const input = document.createElement('input'); input.type = 'hidden'; input.name = key; input.value = data[key]; form.appendChild(input); }
    const csrf = document.createElement('input'); csrf.type = 'hidden'; csrf.name = 'csrf_token'; csrf.value = getCsrfToken();
    form.appendChild(csrf);
    document.body.appendChild(form); form.submit();
}

window.updateSourceStats = updateSourceStats;
window.runAggregator = runAggregator;
window.updateHistory = updateHistory;
window.viewAllHistory = viewAllHistory;
window.updateLogs = updateLogs;
window.clearTerminal = clearTerminal;
window.clearHistory = clearHistory;
window.updateMS365 = updateMS365;
window.updateGitHub = updateGitHub;
window.updateAzure = updateAzure;
window.runSingleSource = runSingleSource;
window.showAddSourceModal = showAddSourceModal;
window.showEditSourceModal = showEditSourceModal;
window.testSource = testSource;
window.showAddWhitelistModal = showAddWhitelistModal;
window.submitForm = submitForm;
