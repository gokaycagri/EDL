/**
 * Dashboard Logic for Threat Feed Aggregator
 * Dark Operations Theme — Relies on window.AppConfig for server-side variables.
 */

// Track previous stat values for flash animation
var prevStats = { total: null, ip: null, domain: null, feeds: null };

document.addEventListener('DOMContentLoaded', function() {
    updateLogs();
    updateHistory();
    updateSourceStats();
    updateScheduledJobs();
    initMap();
    setInterval(updateLogs, 3000);
    setInterval(updateHistory, 10000);
    setInterval(updateSourceStats, 10000);
    setInterval(updateScheduledJobs, 30000);

    // Populate Sources for Generic EDL
    var edlList = document.getElementById('edl_sources_list');
    if (edlList) {
        if (window.AppConfig && window.AppConfig.sourceUrls && window.AppConfig.sourceUrls.length > 0) {
            edlList.textContent = '';
            window.AppConfig.sourceUrls.forEach(function(s, idx) {
                var wrapper = document.createElement('div');
                wrapper.className = 'form-check form-check-sm mb-0';

                var input = document.createElement('input');
                input.className = 'form-check-input source-check';
                input.type = 'checkbox';
                input.name = 'sources';
                input.value = s.name;
                input.id = 'src_chk_' + idx;

                var label = document.createElement('label');
                label.className = 'form-check-label small text-truncate d-block';
                label.setAttribute('for', 'src_chk_' + idx);
                label.title = s.name;
                label.textContent = s.name;

                wrapper.appendChild(input);
                wrapper.appendChild(label);
                edlList.appendChild(wrapper);
            });
        } else {
            edlList.textContent = '';
            var noSrc = document.createElement('div');
            noSrc.className = 'text-muted small text-center';
            noSrc.textContent = 'No sources configured.';
            edlList.appendChild(noSrc);
        }
    }

    // Handle Flash Messages
    if (window.AppConfig && window.AppConfig.flashMessages) {
        window.AppConfig.flashMessages.forEach(function(msg) {
            var icon = (msg.category === 'danger') ? 'error' : msg.category;
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

// === Value Flash Animation ===
function flashStatValue(elementId, newValue) {
    var el = document.getElementById(elementId);
    if (!el) return;
    var oldValue = el.textContent;
    el.textContent = newValue;
    if (oldValue !== String(newValue)) {
        el.classList.remove('value-updated');
        void el.offsetWidth; // force reflow
        el.classList.add('value-updated');
    }
}

// === Source Stats ===
function updateSourceStats() {
    fetch('/api/source_stats')
        .then(function(r) { return r.json(); })
        .then(function(data) {
            var sources = data.sources || {};
            var totals = data.totals || {};
            var countryStats = data.country_stats || [];

            // 1. Update Top Cards with flash
            if (totals.total !== undefined) flashStatValue('stat-total', totals.total);
            if (totals.ip !== undefined) flashStatValue('stat-ip', totals.ip);
            if (totals.domain !== undefined) flashStatValue('stat-domain', totals.domain);
            if (totals.feeds !== undefined) flashStatValue('stat-feeds', totals.feeds);

            // 2. Update Severity Ribbon
            if (typeof window.updateSeverityRibbon === 'function') {
                var degraded = 0;
                for (var name in sources) {
                    var src = sources[name];
                    if (typeof src === 'object' && src.consecutive_failures && src.consecutive_failures >= 3) {
                        degraded++;
                    }
                }
                window.updateSeverityRibbon(totals.total, totals.feeds, degraded);
            }

            // 3. Update Source Table
            for (var sourceName in sources) {
                var stat = sources[sourceName];
                if (typeof stat !== 'object') continue;

                var rows = document.querySelectorAll('tr');
                rows.forEach(function(row) {
                    var nameEl = row.querySelector('strong');
                    if (nameEl && nameEl.textContent === sourceName) {
                        var badge = row.querySelector('.badge');
                        if (badge) badge.textContent = stat.count || 0;

                        var cells = row.querySelectorAll('td');
                        if (cells.length >= 3) {
                            cells[2].textContent = stat.last_updated || 'N/A';
                        }
                    }
                });
            }

            // 4. Update Country Stats Table & Map
            if (countryStats.length > 0) {
                var tbody = document.getElementById('countryStatsTableBody');
                if (tbody) {
                    tbody.textContent = '';
                    countryStats.slice(0, 10).forEach(function(c) {
                        var tr = document.createElement('tr');
                        var td1 = document.createElement('td');
                        td1.className = 'small py-2';
                        td1.textContent = c.country_code;
                        var td2 = document.createElement('td');
                        td2.className = 'text-end small py-2 fw-bold text-primary';
                        td2.textContent = c.count;
                        tr.appendChild(td1);
                        tr.appendChild(td2);
                        tbody.appendChild(tr);
                    });
                }

                if (window.mapInstance) {
                    var mapData = {};
                    countryStats.forEach(function(c) { mapData[c.country_code] = c.count; });
                    if (window.mapInstance.series && window.mapInstance.series.regions && window.mapInstance.series.regions[0]) {
                        window.mapInstance.series.regions[0].setValues(mapData);
                    }
                }
            }
        });
}

// === Aggregator ===
function runAggregator() {
    Swal.fire({
        title: 'Triggering Aggregator', text: 'Process started in background...',
        icon: 'info', timer: 2000, timerProgressBar: true, showConfirmButton: false,
        didOpen: function() { Swal.showLoading(); }
    });
    if (typeof window.addNotification === 'function') {
        window.addNotification('info', 'Aggregator triggered manually');
    }
    fetch('/api/run', { method: 'POST', headers: { 'X-CSRFToken': getCsrfToken() } }).then(function() {
        var count = 0;
        var interval = setInterval(function() {
            updateHistory();
            updateSourceStats();
            if (++count > 10) clearInterval(interval);
        }, 2000);
    });
}

function getCsrfToken() {
    var meta = document.querySelector('meta[name="csrf-token"]');
    return meta ? meta.content : (window.AppConfig ? window.AppConfig.csrfToken : '');
}

// === History ===
function updateHistory() {
    fetch('/api/history?limit=6')
        .then(function(r) {
            if (!r.ok) throw new Error('History fetch failed: ' + r.status);
            return r.json();
        })
        .then(function(data) {
            var tbody = document.getElementById('historyTableBody');
            if (!tbody) return;

            if (!Array.isArray(data) || data.length === 0) {
                tbody.textContent = '';
                var emptyRow = document.createElement('tr');
                var emptyCell = document.createElement('td');
                emptyCell.colSpan = 5;
                emptyCell.className = 'text-center py-3';
                emptyCell.textContent = 'No records.';
                emptyRow.appendChild(emptyCell);
                tbody.appendChild(emptyRow);
                return;
            }

            tbody.textContent = '';
            data.forEach(function(item) {
                var statusClass = item.status === 'success' ? 'bg-success' : (item.status === 'running' ? 'bg-info' : 'bg-danger');
                var tr = document.createElement('tr');

                var td1 = document.createElement('td');
                td1.className = 'ps-4 text-muted small';
                td1.textContent = item.start_time;

                var td2 = document.createElement('td');
                td2.className = 'fw-bold';
                td2.textContent = item.source_name;

                var td3 = document.createElement('td');
                var badge = document.createElement('span');
                badge.className = 'badge ' + statusClass;
                badge.textContent = item.status.toUpperCase();
                td3.appendChild(badge);

                var td4 = document.createElement('td');
                td4.textContent = item.items_processed || 0;

                var td5 = document.createElement('td');
                td5.className = 'text-end pe-4 small text-muted';
                td5.textContent = item.message || '-';

                tr.appendChild(td1);
                tr.appendChild(td2);
                tr.appendChild(td3);
                tr.appendChild(td4);
                tr.appendChild(td5);
                tbody.appendChild(tr);

                // Push notification for errors
                if (item.status === 'error' && typeof window.addNotification === 'function') {
                    window.addNotification('error', 'Feed error: ' + item.source_name + ' - ' + (item.message || 'Unknown'));
                }
            });
        })
        .catch(function(err) { console.error('Update history failed:', err); });
}

function viewAllHistory() {
    fetch('/api/history?limit=100')
        .then(function(r) { return r.json(); })
        .then(function(data) {
            var tbody = document.getElementById('fullHistoryTableBody');
            if (!tbody) return;

            tbody.textContent = '';
            data.forEach(function(item) {
                var statusClass = item.status === 'success' ? 'bg-success' : (item.status === 'running' ? 'bg-info' : 'bg-danger');
                var tr = document.createElement('tr');

                var td1 = document.createElement('td');
                td1.className = 'ps-4 text-muted small';
                td1.textContent = item.start_time;

                var td2 = document.createElement('td');
                td2.className = 'fw-bold';
                td2.textContent = item.source_name;

                var td3 = document.createElement('td');
                var badge = document.createElement('span');
                badge.className = 'badge ' + statusClass;
                badge.textContent = item.status.toUpperCase();
                td3.appendChild(badge);

                var td4 = document.createElement('td');
                td4.textContent = item.items_processed || 0;

                var td5 = document.createElement('td');
                td5.className = 'text-end pe-4 small text-muted';
                td5.textContent = item.message || '-';

                tr.appendChild(td1);
                tr.appendChild(td2);
                tr.appendChild(td3);
                tr.appendChild(td4);
                tr.appendChild(td5);
                tbody.appendChild(tr);
            });

            var historyModal = new bootstrap.Modal(document.getElementById('historyModal'));
            historyModal.show();
        })
        .catch(function() { Swal.fire('Error', 'Failed to load full history', 'error'); });
}

// === Live Logs with Level Counts ===
function updateLogs() {
    var hidePollsEl = document.getElementById('hidePolls');
    var hidePolls = hidePollsEl ? hidePollsEl.checked : true;

    fetch('/api/live_logs')
        .then(function(r) {
            if (!r.ok) throw new Error('Logs fetch failed: ' + r.status);
            return r.json();
        })
        .then(function(data) {
            var logWindow = document.getElementById('logWindow');
            if (!logWindow) return;
            var wasAtBottom = logWindow.scrollHeight - logWindow.clientHeight <= logWindow.scrollTop + 50;

            // Count log levels
            var infoCount = 0, warnCount = 0, errorCount = 0;

            if (data.length === 0) {
                logWindow.textContent = '';
                var waitMsg = document.createElement('div');
                waitMsg.className = 'text-muted';
                waitMsg.style.fontStyle = 'italic';
                waitMsg.textContent = 'Waiting for logs...';
                logWindow.appendChild(waitMsg);
                return;
            }

            logWindow.textContent = '';
            data.forEach(function(line) {
                // Count levels regardless of filter
                if (line.includes('INFO')) infoCount++;
                if (line.includes('WARNING')) warnCount++;
                if (line.includes('ERROR')) errorCount++;

                if (hidePolls && (line.includes('GET /api/') || line.includes('POST /api/') || line.includes('GET /status') || line.includes('GET /static/') || line.includes('GET /login') || line.includes('GET / HTTP/1.1'))) return;

                var div = document.createElement('div');
                div.className = 'log-line mb-1';

                // Advanced Formatting for Access Logs
                var accessLogMatch = line.match(/(?:(?:\d{1,3}\.){3}\d{1,3}) - - \[(.*?)\] "(GET|POST|PUT|DELETE|PATCH) (.*?) HTTP\/[0-9.]+" (\d{3}) -/);

                if (accessLogMatch) {
                    var timestamp = accessLogMatch[1].split(' ')[1];
                    var method = accessLogMatch[2];
                    var path = accessLogMatch[3];
                    var status = accessLogMatch[4];
                    var ipMatch = line.match(/((?:\d{1,3}\.){3}\d{1,3})/);
                    var ip = ipMatch ? ipMatch[0] : 'Unknown';

                    var methodColor = '#60a5fa';
                    if (method === 'POST') methodColor = '#fcd34d';
                    else if (method === 'DELETE') methodColor = '#ff2d55';

                    var statusColor = '#34d399';
                    if (status.startsWith('3')) statusColor = '#94a3b8';
                    else if (status.startsWith('4') || status.startsWith('5')) statusColor = '#ff2d55';

                    var tsSpan = document.createElement('span');
                    tsSpan.style.cssText = 'color:#64748b; font-size:0.8em;';
                    tsSpan.textContent = '[' + timestamp + ']';

                    var ipSpan = document.createElement('span');
                    ipSpan.style.cssText = 'color:#94a3b8; font-size:0.8em; margin-left:5px;';
                    ipSpan.textContent = ip;

                    var methodSpan = document.createElement('span');
                    methodSpan.style.cssText = 'color:' + methodColor + '; font-weight:bold; margin-left:5px;';
                    methodSpan.textContent = method;

                    var pathSpan = document.createElement('span');
                    pathSpan.style.cssText = 'color:#e2e8f0; margin-left:5px;';
                    pathSpan.textContent = path;

                    var statusSpan = document.createElement('span');
                    statusSpan.style.cssText = 'color:' + statusColor + '; font-weight:bold; float:right;';
                    statusSpan.textContent = status;

                    div.appendChild(tsSpan);
                    div.appendChild(ipSpan);
                    div.appendChild(methodSpan);
                    div.appendChild(pathSpan);
                    div.appendChild(statusSpan);
                } else {
                    div.textContent = line;
                    if (line.includes('ERROR')) div.style.color = '#ff2d55';
                    else if (line.includes('WARNING')) div.style.color = '#ff6b35';
                    else if (line.includes('SUCCESS') || line.includes('Completed') || line.includes('Written batch')) div.style.color = '#34d399';
                }

                logWindow.appendChild(div);
            });

            if (wasAtBottom) logWindow.scrollTop = logWindow.scrollHeight;

            // Update log level count badges
            var infoEl = document.getElementById('logCountInfo');
            var warnEl = document.getElementById('logCountWarn');
            var errorEl = document.getElementById('logCountError');
            if (infoEl) infoEl.textContent = infoCount;
            if (warnEl) warnEl.textContent = warnCount;
            if (errorEl) errorEl.textContent = errorCount;
        })
        .catch(function(err) { console.error('Update logs failed:', err); });
}

// === Terminal Fullscreen Toggle ===
function toggleTerminalFullscreen() {
    var card = document.getElementById('terminalCard');
    var logWindow = document.getElementById('logWindow');
    if (!card) return;

    if (card.style.position === 'fixed') {
        // Exit fullscreen
        card.style.position = '';
        card.style.inset = '';
        card.style.zIndex = '';
        card.style.borderRadius = '';
        if (logWindow) logWindow.style.height = '';
    } else {
        // Enter fullscreen
        card.style.position = 'fixed';
        card.style.inset = '0';
        card.style.zIndex = '9000';
        card.style.borderRadius = '0';
        if (logWindow) logWindow.style.height = 'calc(100vh - 70px)';
    }
}

function clearTerminal() {
    if (confirm('Clear all live logs from memory?')) {
        fetch('/api/live_logs/clear', {
            method: 'POST',
            headers: { 'X-CSRFToken': getCsrfToken() }
        })
        .then(function(r) { return r.json(); })
        .then(function() {
            var logWindow = document.getElementById('logWindow');
            if (logWindow) logWindow.textContent = '';
            updateLogs();
        })
        .catch(function(err) { console.error('Failed to clear logs:', err); });
    }
}

function clearHistory() {
    if (confirm('Clear history?')) {
        fetch('/api/history/clear', {
            method: 'POST',
            headers: {
                'X-CSRFToken': getCsrfToken(),
                'Content-Type': 'application/json'
            }
        })
        .then(function(r) {
            if (!r.ok) return r.text().then(function(text) { throw new Error(text || 'Server error ' + r.status); });
            return r.json();
        })
        .then(function(data) {
            if (data.status === 'success') {
                Swal.fire('Cleared!', data.message, 'success');
                updateHistory();
            } else {
                Swal.fire('Error', data.message || 'Failed to clear history', 'error');
            }
        })
        .catch(function(err) {
            console.error('Clear history error:', err);
            Swal.fire('Error', 'Network error: ' + err.message, 'error');
        });
    }
}

// === Service Whitelist Updates ===
function updateMS365() {
    Swal.fire({ title: 'Updating MS365...', didOpen: function() { Swal.showLoading(); } });
    fetch('/api/update_ms365', { method: 'POST', headers: { 'X-CSRFToken': getCsrfToken() } })
        .then(function(r) { return r.json(); })
        .then(function(d) {
            Swal.fire('Result', d.message, d.status);
            if (typeof window.addNotification === 'function') window.addNotification(d.status === 'success' ? 'success' : 'error', 'MS365: ' + d.message);
            updateHistory();
            updateSourceStats();
        });
}

function updateGitHub() {
    Swal.fire({ title: 'Updating GitHub...', didOpen: function() { Swal.showLoading(); } });
    fetch('/api/update_github', { method: 'POST', headers: { 'X-CSRFToken': getCsrfToken() } })
        .then(function(r) { return r.json(); })
        .then(function(d) {
            Swal.fire('Result', d.message, d.status);
            if (typeof window.addNotification === 'function') window.addNotification(d.status === 'success' ? 'success' : 'error', 'GitHub: ' + d.message);
            updateHistory();
            updateSourceStats();
        });
}

function updateAzure() {
    Swal.fire({ title: 'Updating Azure...', didOpen: function() { Swal.showLoading(); } });
    fetch('/api/update_azure', { method: 'POST', headers: { 'X-CSRFToken': getCsrfToken() } })
        .then(function(r) { return r.json(); })
        .then(function(d) {
            Swal.fire('Result', d.message, d.status);
            if (typeof window.addNotification === 'function') window.addNotification(d.status === 'success' ? 'success' : 'error', 'Azure: ' + d.message);
            updateHistory();
            updateSourceStats();
        });
}

function runSingleSource(name) {
    Swal.fire({
        title: 'Triggering ' + name + '...',
        text: 'Fetching fresh data in background',
        icon: 'info', timer: 1500, showConfirmButton: false,
        didOpen: function() { Swal.showLoading(); }
    });

    fetch('/api/run_single/' + encodeURIComponent(name), { method: 'POST', headers: { 'X-CSRFToken': getCsrfToken() } })
        .then(function(r) { return r.json(); })
        .then(function() {
            var count = 0;
            var interval = setInterval(function() {
                updateHistory();
                updateSourceStats();
                if (++count > 8) clearInterval(interval);
            }, 2000);
        })
        .catch(function() { Swal.fire('Error', 'Failed to trigger single fetch', 'error'); });
}

// === Source Modals ===
function showAddSourceModal() {
    Swal.fire({
        title: 'Add Threat Source',
        confirmButtonColor: '#00e5ff',
        html: '<div class="text-start mb-2"><label class="small fw-bold">Name</label><input type="text" id="srcName" class="form-control"></div>' +
              '<div class="text-start mb-2"><label class="small fw-bold">URL</label><input type="text" id="srcUrl" class="form-control"></div>' +
              '<div class="row g-2 mb-2"><div class="col-6"><label class="small fw-bold">Format</label><select id="srcFormat" class="form-select"><option value="text">Text</option><option value="json">JSON</option><option value="csv">CSV</option></select></div><div class="col-6"><label class="small fw-bold">Interval (min)</label><input type="number" id="srcInterval" class="form-control" value="60"></div></div>' +
              '<div class="text-start mb-2"><label class="small fw-bold">JSON Key / CSV Col</label><input type="text" id="srcKey" class="form-control" placeholder="e.g. data.ip (dot notation ok)"><small class="text-muted" style="font-size:0.7rem">Dot notation supported for nested JSON.</small></div>' +
              '<div class="row g-2"><div class="col-6 text-start"><label class="small fw-bold">Auth Username</label><input type="text" id="srcAuthUser" class="form-control" placeholder="Optional"></div><div class="col-6 text-start"><label class="small fw-bold">Auth Password</label><input type="password" id="srcAuthPass" class="form-control" placeholder="Optional"></div></div>',
        confirmButtonText: 'Add', showCancelButton: true,
        preConfirm: function() {
            var name = document.getElementById('srcName').value;
            var url = document.getElementById('srcUrl').value;
            if (!name || !url) Swal.showValidationMessage('Required');
            return {
                name: name, url: url,
                format: document.getElementById('srcFormat').value,
                schedule_interval_minutes: document.getElementById('srcInterval').value,
                key_or_column: document.getElementById('srcKey').value,
                auth_user: document.getElementById('srcAuthUser').value,
                auth_pass: document.getElementById('srcAuthPass').value
            };
        }
    }).then(function(result) { if (result.isConfirmed) submitForm(AppConfig.urls.addSource, result.value); });
}

function showEditSourceModal(index, source) {
    Swal.fire({
        title: 'Edit Source: ' + source.name,
        confirmButtonColor: '#00e5ff',
        html: '<div class="text-start mb-2"><label class="small fw-bold">Name</label><input type="text" id="eName" class="form-control" value="' + source.name + '"></div>' +
              '<div class="text-start mb-2"><label class="small fw-bold">URL</label><input type="text" id="eUrl" class="form-control" value="' + source.url + '"></div>' +
              '<div class="row g-2 mb-2"><div class="col-6"><label class="small fw-bold">Format</label><select id="eFormat" class="form-select"><option value="text" ' + (source.format === 'text' ? 'selected' : '') + '>Text</option><option value="json" ' + (source.format === 'json' ? 'selected' : '') + '>JSON</option><option value="csv" ' + (source.format === 'csv' ? 'selected' : '') + '>CSV</option></select></div><div class="col-6"><label class="small fw-bold">Interval</label><input type="number" id="eInterval" class="form-control" value="' + source.schedule_interval_minutes + '"></div></div>' +
              '<div class="text-start mb-2"><label class="small fw-bold">JSON Key / CSV Col</label><input type="text" id="eKey" class="form-control" value="' + (source.key_or_column || '') + '" placeholder="e.g. data.ip"><small class="text-muted" style="font-size:0.7rem">Dot notation supported for nested JSON.</small></div>' +
              '<div class="row g-2 mb-2"><div class="col-6 text-start"><label class="small fw-bold">Auth User</label><input type="text" id="eAuthUser" class="form-control" value="' + (source.auth_user || '') + '"></div><div class="col-6 text-start"><label class="small fw-bold">Auth Pass</label><input type="password" id="eAuthPass" class="form-control" value="' + (source.auth_pass || '') + '"></div></div>' +
              '<div class="text-start"><label class="small fw-bold">Confidence (0-100)</label><input type="number" id="eConf" class="form-control" value="' + (source.confidence || 50) + '"></div>',
        showCancelButton: true, confirmButtonText: 'Save Changes',
        preConfirm: function() {
            var name = document.getElementById('eName').value;
            var url = document.getElementById('eUrl').value;
            if (!name || !url) Swal.showValidationMessage('Required');
            return {
                name: name, url: url,
                format: document.getElementById('eFormat').value,
                schedule_interval_minutes: document.getElementById('eInterval').value,
                confidence: document.getElementById('eConf').value,
                key_or_column: document.getElementById('eKey').value,
                auth_user: document.getElementById('eAuthUser').value,
                auth_pass: document.getElementById('eAuthPass').value
            };
        }
    }).then(function(res) { if (res.isConfirmed) submitForm('/system/update_source/' + index, res.value); });
}

function testSource(name) {
    Swal.fire({ title: 'Testing Feed...', allowOutsideClick: false, didOpen: function() { Swal.showLoading(); } });
    var sources = AppConfig.sourceUrls;
    var source = sources.find(function(s) { return s.name === name; });
    if (!source) { Swal.fire('Error', 'Not found', 'error'); return; }
    fetch('/api/test_feed', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'X-CSRFToken': getCsrfToken() },
        body: JSON.stringify(source)
    })
    .then(function(r) { return r.json(); })
    .then(function(data) {
        if (data.status === 'success') {
            Swal.fire({
                title: 'Test OK!',
                html: '<div class="text-start text-success fw-bold">' + data.message + '</div><hr><small>Sample:</small><ul class="small"><li>' + data.sample.join('</li><li>') + '</li></ul>',
                icon: 'success'
            });
            updateHistory();
            updateSourceStats();
        } else {
            Swal.fire('Failed', data.message, 'error');
        }
    });
}

// === Safe / Block List Modals ===
function showAddWhitelistModal() {
    Swal.fire({
        title: 'Add to Safe List',
        confirmButtonColor: '#34d399',
        html: '<div class="text-start"><label class="form-label small fw-bold mb-1">IP, CIDR or Domain</label><input id="safe-item" class="swal2-input mt-0 mb-3" style="width: 85%;" placeholder="e.g. 1.2.3.4 or example.com"><label class="form-label small fw-bold mb-1">Description / Context (Optional)</label><input id="safe-desc" class="swal2-input mt-0" style="width: 85%;" placeholder="Why is this safe?"></div>',
        showCancelButton: true, confirmButtonText: 'Add to Safe List',
        preConfirm: function() {
            var item = document.getElementById('safe-item').value;
            var desc = document.getElementById('safe-desc').value;
            if (!item) { Swal.showValidationMessage('Item is required'); return false; }
            return [item, desc];
        }
    }).then(function(result) {
        if (result.isConfirmed) {
            submitForm(AppConfig.urls.addWhitelist, { item: result.value[0], description: result.value[1] || 'Added from Dashboard' });
        }
    });
}

function showAddBlacklistModal() {
    Swal.fire({
        title: 'Add to Block List',
        confirmButtonColor: '#ff2d55',
        html: '<div class="text-start"><label class="form-label small fw-bold mb-1">IP, CIDR or Domain</label><input id="block-item" class="swal2-input mt-0 mb-3" style="width: 85%;" placeholder="e.g. 5.6.7.8"><label class="form-label small fw-bold mb-1">Reason / Context (Optional)</label><input id="block-comment" class="swal2-input mt-0" style="width: 85%;" placeholder="Reason for blocking"></div>',
        showCancelButton: true, confirmButtonText: 'Block Item',
        preConfirm: function() {
            var item = document.getElementById('block-item').value;
            var comment = document.getElementById('block-comment').value;
            if (!item) { Swal.showValidationMessage('Item is required'); return false; }
            return [item, comment];
        }
    }).then(function(result) {
        if (result.isConfirmed) {
            submitForm(AppConfig.urls.addBlacklist, { item: result.value[0], comment: result.value[1] || 'Manual block' });
        }
    });
}

// === Map (Dark Operations Colors) ===
function initMap() {
    var data = AppConfig.countryStats;
    try {
        if (typeof jsVectorMap !== 'undefined') {
            window.mapInstance = new jsVectorMap({
                selector: '#world-map',
                map: 'world',
                zoomOnScroll: false,
                zoomButtons: true,
                regionStyle: {
                    initial: { fill: '#1a2233', stroke: '#243044', strokeWidth: 0.5 },
                    hover: { fill: '#243044' }
                },
                visualizeData: {
                    scale: ['#1a2233', '#00e5ff'],
                    values: data
                },
                onRegionTooltipShow: function(event, tooltip, code) {
                    var count = data[code] || 0;
                    tooltip.text(
                        '<div class="p-2" style="font-family: IBM Plex Mono, monospace;">' +
                        '<h6 class="mb-1" style="color:#e2e8f0;">' + tooltip.text() + '</h6>' +
                        '<span style="background:rgba(0,229,255,0.15); color:#00e5ff; padding:2px 8px; border-radius:4px; font-size:0.75rem; font-weight:600;">' + count + ' Indicators</span></div>',
                        { isHtml: true }
                    );
                }
            });

            var mapEl = document.getElementById('world-map');
            if (mapEl) {
                mapEl.addEventListener('wheel', function(e) {
                    if (e.ctrlKey) {
                        e.preventDefault();
                        if (window.mapInstance) {
                            if (e.deltaY < 0) window.mapInstance.setScale(window.mapInstance.scale * 1.2, e.offsetX, e.offsetY);
                            else window.mapInstance.setScale(window.mapInstance.scale / 1.2, e.offsetX, e.offsetY);
                        }
                    }
                }, { passive: false });
            }
        }
    } catch (e) { console.error(e); }
}

// === Schedules ===
function updateScheduledJobs() {
    fetch('/api/scheduled_jobs')
        .then(function(r) { return r.json(); })
        .then(function(data) {
            var tbody = document.getElementById('scheduledJobsTableBody');
            if (!tbody) return;

            if (data.length === 0) {
                tbody.textContent = '';
                var emptyRow = document.createElement('tr');
                var emptyCell = document.createElement('td');
                emptyCell.colSpan = 2;
                emptyCell.className = 'text-center py-3 text-muted';
                emptyCell.textContent = 'No active schedules.';
                emptyRow.appendChild(emptyCell);
                tbody.appendChild(emptyRow);
                return;
            }

            tbody.textContent = '';
            data.slice(0, 4).forEach(function(job) {
                var tr = document.createElement('tr');
                var td1 = document.createElement('td');
                td1.className = 'ps-3 py-2';
                var strong = document.createElement('strong');
                strong.textContent = job.name;
                td1.appendChild(strong);
                td1.appendChild(document.createElement('br'));
                var timeSpan = document.createElement('span');
                timeSpan.className = 'text-muted';
                timeSpan.style.fontSize = '0.7em';
                timeSpan.textContent = job.next_run_time;
                td1.appendChild(timeSpan);

                var td2 = document.createElement('td');
                td2.className = 'text-end pe-3 text-primary fw-bold';
                td2.textContent = job.time_until;

                tr.appendChild(td1);
                tr.appendChild(td2);
                tbody.appendChild(tr);
            });
        })
        .catch(function(err) { console.error('Failed to update schedules:', err); });
}

function viewAllSchedules() {
    fetch('/api/scheduled_jobs')
        .then(function(r) { return r.json(); })
        .then(function(data) {
            var tbody = document.getElementById('allSchedulesTableBody');
            if (!tbody) return;

            tbody.textContent = '';
            data.forEach(function(job) {
                var tr = document.createElement('tr');
                var td1 = document.createElement('td');
                td1.className = 'ps-4 py-2';
                var strong = document.createElement('strong');
                strong.textContent = job.name;
                td1.appendChild(strong);

                var td2 = document.createElement('td');
                td2.textContent = job.next_run_time;

                var td3 = document.createElement('td');
                td3.className = 'text-end pe-4 text-primary fw-bold';
                td3.textContent = job.time_until;

                tr.appendChild(td1);
                tr.appendChild(td2);
                tr.appendChild(td3);
                tbody.appendChild(tr);
            });

            var modal = new bootstrap.Modal(document.getElementById('schedulesModal'));
            modal.show();
        });
}

// === Clipboard ===
function copyToClipboard(elementId) {
    var el = document.getElementById(elementId);
    if (!el) return;
    el.select();
    el.setSelectionRange(0, 99999);
    navigator.clipboard.writeText(el.value).then(function() {
        Swal.fire({ title: 'Copied!', text: 'URL copied to clipboard.', icon: 'success', timer: 1500, toast: true, position: 'top-end', showConfirmButton: false });
    });
}

function copyRawToClipboard(text) {
    navigator.clipboard.writeText(text).then(function() {
        Swal.fire({ title: 'Copied!', text: 'Direct URL copied to clipboard.', icon: 'success', timer: 1500, toast: true, position: 'top-end', showConfirmButton: false });
    });
}

function toggleAllSources() {
    var checks = document.querySelectorAll('.source-check');
    if (checks.length === 0) return;
    var allChecked = Array.from(checks).every(function(c) { return c.checked; });
    checks.forEach(function(c) { c.checked = !allChecked; });
}

// === Edit List Modals ===
function showEditSafeListModal(id, currentItem, currentType, currentDesc) {
    Swal.fire({
        title: 'Edit Safe List Item',
        confirmButtonColor: '#00e5ff',
        html: '<div class="mb-3 text-start"><label class="form-label small fw-bold">Item (IP/Domain/URL)</label><input type="text" id="editSafeItem" class="form-control" value="' + currentItem + '"></div>' +
              '<div class="mb-3 text-start"><label class="form-label small fw-bold">Type</label><select id="editSafeType" class="form-select"><option value="ip" ' + (currentType === 'ip' ? 'selected' : '') + '>IP</option><option value="domain" ' + (currentType === 'domain' ? 'selected' : '') + '>Domain</option><option value="url" ' + (currentType === 'url' ? 'selected' : '') + '>URL</option></select></div>' +
              '<div class="mb-3 text-start"><label class="form-label small fw-bold">Description</label><input type="text" id="editSafeDesc" class="form-control" value="' + currentDesc + '"></div>',
        showCancelButton: true, confirmButtonText: 'Update',
        preConfirm: function() {
            var item = document.getElementById('editSafeItem').value;
            if (!item) Swal.showValidationMessage('Item cannot be empty');
            return { id: id, item: item, type: document.getElementById('editSafeType').value, description: document.getElementById('editSafeDesc').value };
        }
    }).then(function(result) { if (result.isConfirmed) submitForm('/system/whitelist/update', result.value); });
}

function showEditBlockListModal(id, currentItem, currentType, currentComment) {
    Swal.fire({
        title: 'Edit Block List Item',
        confirmButtonColor: '#00e5ff',
        html: '<div class="mb-3 text-start"><label class="form-label small fw-bold">Item (IP/Domain/URL)</label><input type="text" id="editBlockItem" class="form-control" value="' + currentItem + '"></div>' +
              '<div class="mb-3 text-start"><label class="form-label small fw-bold">Type</label><select id="editBlockType" class="form-select"><option value="ip" ' + (currentType === 'ip' ? 'selected' : '') + '>IP</option><option value="domain" ' + (currentType === 'domain' ? 'selected' : '') + '>Domain</option><option value="url" ' + (currentType === 'url' ? 'selected' : '') + '>URL</option></select></div>' +
              '<div class="mb-3 text-start"><label class="form-label small fw-bold">Comment</label><input type="text" id="editBlockComment" class="form-control" value="' + currentComment + '"></div>',
        showCancelButton: true, confirmButtonText: 'Update',
        preConfirm: function() {
            var item = document.getElementById('editBlockItem').value;
            if (!item) Swal.showValidationMessage('Item cannot be empty');
            return { id: id, item: item, type: document.getElementById('editBlockType').value, comment: document.getElementById('editBlockComment').value };
        }
    }).then(function(result) { if (result.isConfirmed) submitForm('/system/blacklist/update', result.value); });
}

// === Import List Modals ===
function showImportWhitelistModal() {
    Swal.fire({
        title: 'Import Safe List',
        html: '<div class="mb-3 text-start"><label class="form-label small fw-bold">Select File (TXT, JSON, XML)</label><input type="file" id="importFile" class="form-control" accept=".txt,.json,.xml"><small class="text-muted">Supports lists of IPs, CIDRs, or Domains.</small></div>',
        showCancelButton: true, confirmButtonText: 'Import',
        preConfirm: function() {
            var file = document.getElementById('importFile').files[0];
            if (!file) Swal.showValidationMessage('Please select a file');
            return file;
        }
    }).then(function(result) { if (result.isConfirmed) uploadFile('/system/whitelist/import', result.value); });
}

function showImportBlacklistModal() {
    Swal.fire({
        title: 'Import Block List',
        html: '<div class="mb-3 text-start"><label class="form-label small fw-bold">Select File (TXT, JSON, XML)</label><input type="file" id="importFile" class="form-control" accept=".txt,.json,.xml"><small class="text-muted">Supports lists of IPs, CIDRs, or Domains.</small></div>',
        showCancelButton: true, confirmButtonText: 'Import',
        preConfirm: function() {
            var file = document.getElementById('importFile').files[0];
            if (!file) Swal.showValidationMessage('Please select a file');
            return file;
        }
    }).then(function(result) { if (result.isConfirmed) uploadFile('/system/blacklist/import', result.value); });
}

function uploadFile(url, file) {
    var formData = new FormData();
    formData.append('import_file', file);
    formData.append('csrf_token', getCsrfToken());

    Swal.fire({ title: 'Importing...', text: 'Parsing and validating file content.', didOpen: function() { Swal.showLoading(); } });

    fetch(url, { method: 'POST', body: formData })
        .then(function(response) {
            if (response.redirected) { window.location.href = response.url; }
            else { window.location.reload(); }
        })
        .catch(function(error) { Swal.fire('Error', 'Upload failed: ' + error, 'error'); });
}

// === Form Submission ===
function submitForm(action, data) {
    var form = document.createElement('form');
    form.method = 'POST';
    form.action = action;
    form.style.display = 'none';
    for (var key in data) {
        if (data.hasOwnProperty(key)) {
            var input = document.createElement('input');
            input.type = 'hidden';
            input.name = key;
            input.value = data[key];
            form.appendChild(input);
        }
    }
    var csrf = document.createElement('input');
    csrf.type = 'hidden';
    csrf.name = 'csrf_token';
    csrf.value = getCsrfToken();
    form.appendChild(csrf);
    document.body.appendChild(form);
    form.submit();
}

// === Global Exports ===
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
window.showAddSourceModal = showAddSourceModal;
window.showEditSourceModal = showEditSourceModal;
window.showAddWhitelistModal = showAddWhitelistModal;
window.showAddBlacklistModal = showAddBlacklistModal;
window.showImportWhitelistModal = showImportWhitelistModal;
window.showImportBlacklistModal = showImportBlacklistModal;
window.showEditSafeListModal = showEditSafeListModal;
window.showEditBlockListModal = showEditBlockListModal;
window.toggleTerminalFullscreen = toggleTerminalFullscreen;
window.submitForm = submitForm;
