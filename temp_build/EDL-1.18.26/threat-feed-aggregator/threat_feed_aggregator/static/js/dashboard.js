/**
 * Dashboard Logic for Threat Feed Aggregator
 * Relies on window.AppConfig for server-side variables.
 */

document.addEventListener('DOMContentLoaded', function() {
    updateLogs();
    updateHistory();
    updateSourceStats();
    updateScheduledJobs();
    initMap();
    setInterval(updateLogs, 3000); 
    setInterval(updateHistory, 10000);
    setInterval(updateSourceStats, 10000);
    setInterval(updateScheduledJobs, 30000); // Update schedules every 30s

    // Populate Sources for Generic EDL
    const edlList = document.getElementById('edl_sources_list');
    if (edlList) {
        if (window.AppConfig && window.AppConfig.sourceUrls && window.AppConfig.sourceUrls.length > 0) {
            console.log('Populating Custom EDL sources:', window.AppConfig.sourceUrls.length);
            let html = '';
            window.AppConfig.sourceUrls.forEach((s, idx) => {
                html += `
                    <div class="form-check form-check-sm mb-0">
                        <input class="form-check-input source-check" type="checkbox" name="sources" value="${s.name}" id="src_chk_${idx}">
                        <label class="form-check-label small text-truncate d-block" for="src_chk_${idx}" title="${s.name}">
                            ${s.name}
                        </label>
                    </div>
                `;
            });
            edlList.innerHTML = html;
        } else {
            console.warn('No sourceUrls found in AppConfig');
            edlList.innerHTML = '<div class="text-muted small text-center">No sources configured.</div>';
        }
    }

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
            const countryStats = data.country_stats || [];

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

            // 3. Update Country Stats Table & Map
            if (countryStats.length > 0) {
                const tbody = document.getElementById('countryStatsTableBody');
                if (tbody) {
                    let html = '';
                    // Show only top 10 in the table to prevent overcrowding
                    countryStats.slice(0, 10).forEach(c => {
                        html += `<tr><td class="small py-2">${c.country_code}</td><td class="text-end small py-2 fw-bold text-primary">${c.count}</td></tr>`;
                    });
                    tbody.innerHTML = html;
                }

                // Update Map
                if (window.mapInstance) {
                    const mapData = {};
                    countryStats.forEach(c => { mapData[c.country_code] = c.count; });
                    // jsVectorMap method to update region values
                    if (window.mapInstance.series && window.mapInstance.series.regions && window.mapInstance.series.regions[0]) {
                        window.mapInstance.series.regions[0].setValues(mapData);
                    }
                }
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
                if (hidePolls && (line.includes('GET /api/') || line.includes('POST /api/') || line.includes('GET /status') || line.includes('GET /static/') || line.includes('GET /login') || line.includes('GET / HTTP/1.1'))) return;
                
                const div = document.createElement('div'); 
                div.className = 'log-line mb-1';
                
                // Advanced Formatting for Access Logs
                // Example: ... 172.18.0.1 - - [29/Dec/2025 22:43:21] "POST /system/blacklist/add HTTP/1.1" 302 -
                const accessLogMatch = line.match(/(?:(?:\d{1,3}\.){3}\d{1,3}) - - \[(.*?)\] "(GET|POST|PUT|DELETE|PATCH) (.*?) HTTP\/[0-9.]+" (\d{3}) -/);
                
                if (accessLogMatch) {
                    const timestamp = accessLogMatch[1].split(' ')[1]; // Just the time part
                    const method = accessLogMatch[2];
                    const path = accessLogMatch[3];
                    const status = accessLogMatch[4];
                    const ipMatch = line.match(/((?:\d{1,3}\.){3}\d{1,3})/);
                    const ip = ipMatch ? ipMatch[0] : 'Unknown';

                    let methodColor = '#60a5fa'; // Blue for GET
                    if (method === 'POST') methodColor = '#fcd34d'; // Yellow for POST
                    else if (method === 'DELETE') methodColor = '#f87171'; // Red
                    
                    let statusColor = '#4ade80'; // Green for 200
                    if (status.startsWith('3')) statusColor = '#94a3b8'; // Grey/Blue for 300
                    else if (status.startsWith('4') || status.startsWith('5')) statusColor = '#f87171'; // Red for errors

                    div.innerHTML = `
                        <span style="color:#64748b; font-size:0.8em;">[${timestamp}]</span>
                        <span style="color:#94a3b8; font-size:0.8em;">${ip}</span>
                        <span style="color:${methodColor}; font-weight:bold; margin-left:5px;">${method}</span>
                        <span style="color:#e2e8f0;">${path}</span>
                        <span style="color:${statusColor}; font-weight:bold; float:right;">${status}</span>
                    `;
                } else if (line.includes(' "GET ') || line.includes(' "POST ') || line.includes(' "PUT ') || line.includes(' "DELETE ')) {
                    // Fallback for non-standard or partial lines
                    const parts = line.split(' "');
                    if (parts.length > 1) {
                        const prefix = parts[0];
                        const rest = parts[1];
                        const methodUrl = rest.split('"')[0];
                        const status = rest.split('"')[1] || '';
                        div.innerHTML = `<span style="color:#aaa">${prefix}</span> <span style="color:#60a5fa; font-weight:bold;">"${methodUrl}"</span><span style="color:#fcd34d">${status}</span>`;
                    } else {
                        div.textContent = line;
                    }
                } else {
                    div.textContent = line;
                    if (line.includes('ERROR')) div.style.color = '#f87171'; 
                    else if (line.includes('WARNING')) div.style.color = '#fbbf24'; 
                    else if (line.includes('SUCCESS') || line.includes('Completed') || line.includes('Written batch')) div.style.color = '#4ade80';
                }
                
                logWindow.appendChild(div);
            });
            if (wasAtBottom) logWindow.scrollTop = logWindow.scrollHeight;
        })
        .catch(err => console.error('Update logs failed:', err));
}

function clearTerminal() { 
    if(confirm('Clear all live logs from memory?')) {
        fetch('/api/live_logs/clear', { 
            method: 'POST', 
            headers: { 'X-CSRFToken': getCsrfToken() } 
        })
        .then(r => r.json())
        .then(data => {
            const logWindow = document.getElementById('logWindow');
            if (logWindow) logWindow.textContent = ''; 
            updateLogs();
        })
        .catch(err => console.error('Failed to clear logs:', err));
    }
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
    Swal.fire({
        title: `Triggering ${name}...`, 
        text: 'Fetching fresh data in background',
        icon: 'info', 
        timer: 1500, 
        showConfirmButton: false, 
        didOpen: () => { Swal.showLoading(); }
    }); 
    
    fetch(`/api/run_single/${encodeURIComponent(name)}`)
        .then(r => r.json())
        .then(data => {
            // Poll for updates for the next 15 seconds
            let count = 0;
            const interval = setInterval(() => {
                updateHistory(); 
                updateSourceStats();
                if (++count > 8) clearInterval(interval);
            }, 2000);
        })
        .catch(err => Swal.fire('Error', 'Failed to trigger single fetch', 'error'));
}

function showAddSourceModal() {
    Swal.fire({
        title: 'Add Threat Source',
        html: `
            <div class="text-start mb-2"><label class="small fw-bold">Name</label><input type="text" id="srcName" class="form-control"></div>
            <div class="text-start mb-2"><label class="small fw-bold">URL</label><input type="text" id="srcUrl" class="form-control"></div>
            <div class="row g-2 mb-2">
                <div class="col-6"><label class="small fw-bold">Format</label><select id="srcFormat" class="form-select"><option value="text">Text</option><option value="json">JSON</option><option value="csv">CSV</option></select></div>
                <div class="col-6"><label class="small fw-bold">Interval (min)</label><input type="number" id="srcInterval" class="form-control" value="60"></div>
            </div>
            <div class="text-start mb-2"><label class="small fw-bold">JSON Key / CSV Col</label><input type="text" id="srcKey" class="form-control" placeholder="e.g. data.ip (dot notation ok)"><small class="text-muted" style="font-size:0.7rem">Dot notation supported for nested JSON.</small></div>
            <div class="row g-2">
                <div class="col-6 text-start"><label class="small fw-bold">Auth Username</label><input type="text" id="srcAuthUser" class="form-control" placeholder="Optional"></div>
                <div class="col-6 text-start"><label class="small fw-bold">Auth Password</label><input type="password" id="srcAuthPass" class="form-control" placeholder="Optional"></div>
            </div>
        `,
        confirmButtonText: 'Add', showCancelButton: true,
        preConfirm: () => { 
            const name = document.getElementById('srcName').value; const url = document.getElementById('srcUrl').value;
            if (!name || !url) Swal.showValidationMessage('Required');
            return { 
                name, url, 
                format: document.getElementById('srcFormat').value, 
                schedule_interval_minutes: document.getElementById('srcInterval').value,
                key_or_column: document.getElementById('srcKey').value,
                auth_user: document.getElementById('srcAuthUser').value,
                auth_pass: document.getElementById('srcAuthPass').value
            };
        }
    }).then(result => { if (result.isConfirmed) submitForm(AppConfig.urls.addSource, result.value); });
}

function showEditSourceModal(index, source) {
    Swal.fire({
        title: `Edit Source: ${source.name}`,
        html: `
            <div class="text-start mb-2"><label class="small fw-bold">Name</label><input type="text" id="eName" class="form-control" value="${source.name}"></div>
            <div class="text-start mb-2"><label class="small fw-bold">URL</label><input type="text" id="eUrl" class="form-control" value="${source.url}"></div>
            <div class="row g-2 mb-2">
                <div class="col-6"><label class="small fw-bold">Format</label><select id="eFormat" class="form-select"><option value="text" ${source.format==='text'?'selected':''}>Text</option><option value="json" ${source.format==='json'?'selected':''}>JSON</option><option value="csv" ${source.format==='csv'?'selected':''}>CSV</option></select></div>
                <div class="col-6"><label class="small fw-bold">Interval</label><input type="number" id="eInterval" class="form-control" value="${source.schedule_interval_minutes}"></div>
            </div>
            <div class="text-start mb-2"><label class="small fw-bold">JSON Key / CSV Col</label><input type="text" id="eKey" class="form-control" value="${source.key_or_column || ''}" placeholder="e.g. data.ip"><small class="text-muted" style="font-size:0.7rem">Dot notation supported for nested JSON.</small></div>
            <div class="row g-2 mb-2">
                <div class="col-6 text-start"><label class="small fw-bold">Auth User</label><input type="text" id="eAuthUser" class="form-control" value="${source.auth_user || ''}"></div>
                <div class="col-6 text-start"><label class="small fw-bold">Auth Pass</label><input type="password" id="eAuthPass" class="form-control" value="${source.auth_pass || ''}"></div>
            </div>
            <div class="text-start"><label class="small fw-bold">Confidence (0-100)</label><input type="number" id="eConf" class="form-control" value="${source.confidence || 50}"></div>
        `,
        showCancelButton: true, confirmButtonText: 'Save Changes',
        preConfirm: () => { 
            const name = document.getElementById('eName').value; 
            const url = document.getElementById('eUrl').value; 
            if (!name || !url) Swal.showValidationMessage(`Required`); 
            return { 
                name, url, 
                format: document.getElementById('eFormat').value, 
                schedule_interval_minutes: document.getElementById('eInterval').value, 
                confidence: document.getElementById('eConf').value,
                key_or_column: document.getElementById('eKey').value,
                auth_user: document.getElementById('eAuthUser').value,
                auth_pass: document.getElementById('eAuthPass').value
            }; 
        }
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
    Swal.fire({
        title: 'Add to Safe List',
        html: `
            <div class="text-start">
                <label class="form-label small fw-bold mb-1">IP, CIDR or Domain</label>
                <input id="safe-item" class="swal2-input mt-0 mb-3" style="width: 85%;" placeholder="e.g. 1.2.3.4 or example.com">
                <label class="form-label small fw-bold mb-1">Description / Context (Optional)</label>
                <input id="safe-desc" class="swal2-input mt-0" style="width: 85%;" placeholder="Why is this safe?">
            </div>
        `,
        showCancelButton: true,
        confirmButtonText: 'Add to Safe List',
        confirmButtonColor: '#2dce89',
        preConfirm: () => {
            const item = document.getElementById('safe-item').value;
            const desc = document.getElementById('safe-desc').value;
            if (!item) {
                Swal.showValidationMessage('Item is required');
                return false;
            }
            return [item, desc];
        }
    }).then(result => {
        if (result.isConfirmed) {
            const [item, description] = result.value;
            submitForm(AppConfig.urls.addWhitelist, { 
                item: item, 
                description: description || 'Added from Dashboard' 
            });
        }
    });
}

function showAddBlacklistModal() {
    Swal.fire({
        title: 'Add to Block List',
        html: `
            <div class="text-start">
                <label class="form-label small fw-bold mb-1">IP, CIDR or Domain</label>
                <input id="block-item" class="swal2-input mt-0 mb-3" style="width: 85%;" placeholder="e.g. 5.6.7.8">
                <label class="form-label small fw-bold mb-1">Reason / Context (Optional)</label>
                <input id="block-comment" class="swal2-input mt-0" style="width: 85%;" placeholder="Reason for blocking">
            </div>
        `,
        showCancelButton: true,
        confirmButtonText: 'Block Item',
        confirmButtonColor: '#f5365c',
        preConfirm: () => {
            const item = document.getElementById('block-item').value;
            const comment = document.getElementById('block-comment').value;
            if (!item) {
                Swal.showValidationMessage('Item is required');
                return false;
            }
            return [item, comment];
        }
    }).then(result => {
        if (result.isConfirmed) {
            const [item, comment] = result.value;
            submitForm(AppConfig.urls.addBlacklist, { 
                item: item, 
                comment: comment || 'Manual block' 
            });
        }
    });
}
function initMap() {
    const data = AppConfig.countryStats;
    try { 
        if (typeof jsVectorMap !== 'undefined') { 
            window.mapInstance = new jsVectorMap({ 
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

function updateScheduledJobs() {
    fetch('/api/scheduled_jobs')
        .then(r => r.json())
        .then(data => {
            const tbody = document.getElementById('scheduledJobsTableBody');
            if (!tbody) return;
            
            if (data.length === 0) {
                tbody.innerHTML = '<tr><td colspan="2" class="text-center py-3 text-muted">No active schedules.</td></tr>';
                return;
            }

            // Show top 4 nearest tasks on dashboard
            let html = '';
            data.slice(0, 4).forEach(job => {
                html += `<tr><td class="ps-3 py-2"><strong>${job.name}</strong><br><span class="text-muted" style="font-size: 0.7em;">${job.next_run_time}</span></td><td class="text-end pe-3 text-primary fw-bold">${job.time_until}</td></tr>`;
            });
            tbody.innerHTML = html;
        })
        .catch(err => console.error('Failed to update schedules:', err));
}

function viewAllSchedules() {
    fetch('/api/scheduled_jobs')
        .then(r => r.json())
        .then(data => {
            const tbody = document.getElementById('allSchedulesTableBody');
            if (!tbody) return;
            
            let html = '';
            data.forEach(job => {
                html += `<tr><td class="ps-4 py-2"><strong>${job.name}</strong></td><td>${job.next_run_time}</td><td class="text-end pe-4 text-primary fw-bold">${job.time_until}</td></tr>`;
            });
            tbody.innerHTML = html;
            
            const modal = new bootstrap.Modal(document.getElementById('schedulesModal'));
            modal.show();
        });
}

function copyToClipboard(elementId) {
    const el = document.getElementById(elementId);
    if (!el) return;
    
    el.select();
    el.setSelectionRange(0, 99999); /* For mobile devices */
    
    navigator.clipboard.writeText(el.value).then(() => {
        Swal.fire({
            title: 'Copied!',
            text: 'URL copied to clipboard.',
            icon: 'success',
            timer: 1500,
            toast: true,
            position: 'top-end',
            showConfirmButton: false
        });
    });
}

function copyRawToClipboard(text) {
    navigator.clipboard.writeText(text).then(() => {
        Swal.fire({
            title: 'Copied!',
            text: 'Direct URL copied to clipboard.',
            icon: 'success',
            timer: 1500,
            toast: true,
            position: 'top-end',
            showConfirmButton: false
        });
    });
}

function toggleAllSources() {
    const checks = document.querySelectorAll('.source-check');
    if (checks.length === 0) return;
    
    // Check if all are currently checked
    const allChecked = Array.from(checks).every(c => c.checked);
    checks.forEach(c => c.checked = !allChecked);
}

window.updateSourceStats = updateSourceStats;
window.runAggregator = runAggregator;
window.updateHistory = updateHistory;
window.viewAllHistory = viewAllHistory;
window.updateScheduledJobs = updateScheduledJobs;
window.viewAllSchedules = viewAllSchedules;
window.copyToClipboard = copyToClipboard;
window.copyRawToClipboard = copyRawToClipboard;
window.toggleAllSources = toggleAllSources;
window.updateLogs = updateLogs;
window.clearTerminal = clearTerminal;
window.clearHistory = clearHistory;
window.updateMS365 = updateMS365;
window.updateGitHub = updateGitHub;
window.updateAzure = updateAzure;
window.runSingleSource = runSingleSource;
window.testSource = testSource;
window.showAddWhitelistModal = showAddWhitelistModal;
window.showAddBlacklistModal = showAddBlacklistModal;

// Functions for importing lists
function showImportWhitelistModal() {
    Swal.fire({
        title: 'Import Safe List',
        html: `
            <div class="mb-3 text-start">
                <label class="form-label small fw-bold">Select File (TXT, JSON, XML)</label>
                <input type="file" id="importFile" class="form-control" accept=".txt,.json,.xml">
                <small class="text-muted">Supports lists of IPs, CIDRs, or Domains.</small>
            </div>
        `,
        showCancelButton: true,
        confirmButtonText: 'Import',
        preConfirm: () => {
            const file = document.getElementById('importFile').files[0];
            if (!file) Swal.showValidationMessage('Please select a file');
            return file;
        }
    }).then(result => {
        if (result.isConfirmed) {
            uploadFile('/system/whitelist/import', result.value);
        }
    });
}

function showImportBlacklistModal() {
    Swal.fire({
        title: 'Import Block List',
        html: `
            <div class="mb-3 text-start">
                <label class="form-label small fw-bold">Select File (TXT, JSON, XML)</label>
                <input type="file" id="importFile" class="form-control" accept=".txt,.json,.xml">
                <small class="text-muted">Supports lists of IPs, CIDRs, or Domains.</small>
            </div>
        `,
        showCancelButton: true,
        confirmButtonText: 'Import',
        preConfirm: () => {
            const file = document.getElementById('importFile').files[0];
            if (!file) Swal.showValidationMessage('Please select a file');
            return file;
        }
    }).then(result => {
        if (result.isConfirmed) {
            uploadFile('/system/blacklist/import', result.value);
        }
    });
}

function uploadFile(url, file) {
    const formData = new FormData();
    formData.append('import_file', file);
    formData.append('csrf_token', getCsrfToken());

    Swal.fire({
        title: 'Importing...',
        text: 'Parsing and validating file content.',
        didOpen: () => Swal.showLoading()
    });

    fetch(url, {
        method: 'POST',
        body: formData
    })
    .then(response => {
        if (response.redirected) {
            window.location.href = response.url;
        } else {
            window.location.reload();
        }
    })
    .catch(error => {
        Swal.fire('Error', 'Upload failed: ' + error, 'error');
    });
}

window.showImportWhitelistModal = showImportWhitelistModal;
window.showImportBlacklistModal = showImportBlacklistModal;

function showEditSafeListModal(id, currentItem, currentType, currentDesc) {
    Swal.fire({
        title: 'Edit Safe List Item',
        html: `
            <div class="mb-3 text-start">
                <label class="form-label small fw-bold">Item (IP/Domain/URL)</label>
                <input type="text" id="editSafeItem" class="form-control" value="${currentItem}">
            </div>
            <div class="mb-3 text-start">
                <label class="form-label small fw-bold">Type</label>
                <select id="editSafeType" class="form-select">
                    <option value="ip" ${currentType === 'ip' ? 'selected' : ''}>IP</option>
                    <option value="domain" ${currentType === 'domain' ? 'selected' : ''}>Domain</option>
                    <option value="url" ${currentType === 'url' ? 'selected' : ''}>URL</option>
                </select>
            </div>
            <div class="mb-3 text-start">
                <label class="form-label small fw-bold">Description</label>
                <input type="text" id="editSafeDesc" class="form-control" value="${currentDesc}">
            </div>
        `,
        showCancelButton: true,
        confirmButtonText: 'Update',
        preConfirm: () => {
            const item = document.getElementById('editSafeItem').value;
            const type = document.getElementById('editSafeType').value;
            const desc = document.getElementById('editSafeDesc').value;
            if (!item) Swal.showValidationMessage('Item cannot be empty');
            return { id: id, item: item, type: type, description: desc };
        }
    }).then(result => {
        if (result.isConfirmed) {
            submitForm('/system/whitelist/update', result.value);
        }
    });
}

function showEditBlockListModal(id, currentItem, currentType, currentComment) {
    Swal.fire({
        title: 'Edit Block List Item',
        html: `
            <div class="mb-3 text-start">
                <label class="form-label small fw-bold">Item (IP/Domain/URL)</label>
                <input type="text" id="editBlockItem" class="form-control" value="${currentItem}">
            </div>
            <div class="mb-3 text-start">
                <label class="form-label small fw-bold">Type</label>
                <select id="editBlockType" class="form-select">
                    <option value="ip" ${currentType === 'ip' ? 'selected' : ''}>IP</option>
                    <option value="domain" ${currentType === 'domain' ? 'selected' : ''}>Domain</option>
                    <option value="url" ${currentType === 'url' ? 'selected' : ''}>URL</option>
                </select>
            </div>
            <div class="mb-3 text-start">
                <label class="form-label small fw-bold">Comment</label>
                <input type="text" id="editBlockComment" class="form-control" value="${currentComment}">
            </div>
        `,
        showCancelButton: true,
        confirmButtonText: 'Update',
        preConfirm: () => {
            const item = document.getElementById('editBlockItem').value;
            const type = document.getElementById('editBlockType').value;
            const comment = document.getElementById('editBlockComment').value;
            if (!item) Swal.showValidationMessage('Item cannot be empty');
            return { id: id, item: item, type: type, comment: comment };
        }
    }).then(result => {
        if (result.isConfirmed) {
            submitForm('/system/blacklist/update', result.value);
        }
    });
}

window.showEditSafeListModal = showEditSafeListModal;
window.showEditBlockListModal = showEditBlockListModal;

function submitForm(action, data) {
    const form = document.createElement('form'); form.method = 'POST'; form.action = action;
    for (const key in data) { const input = document.createElement('input'); input.type = 'hidden'; input.name = key; input.value = data[key]; form.appendChild(input); }
    const csrf = document.createElement('input'); csrf.type = 'hidden'; csrf.name = 'csrf_token'; csrf.value = getCsrfToken();
    form.appendChild(csrf);
    document.body.appendChild(form); form.submit();
}
window.submitForm = submitForm;
