/**
 * Shared Source Management Logic
 * Used by both Dashboard and System Settings pages.
 * Requires: SweetAlert2 (Swal), AppConfig (or manually passed URLs)
 */

function getCsrfToken() {
    const meta = document.querySelector('meta[name="csrf-token"]');
    if (meta) return meta.content;
    if (window.AppConfig && window.AppConfig.csrfToken) return window.AppConfig.csrfToken;
    return '';
}

function submitForm(action, data) {
    const form = document.createElement('form'); 
    form.method = 'POST'; 
    form.action = action;
    
    for (const key in data) { 
        const input = document.createElement('input'); 
        input.type = 'hidden'; 
        input.name = key; 
        input.value = data[key]; 
        form.appendChild(input); 
    }
    
    const csrf = document.createElement('input'); 
    csrf.type = 'hidden'; 
    csrf.name = 'csrf_token'; 
    csrf.value = getCsrfToken();
    form.appendChild(csrf);
    
    document.body.appendChild(form); 
    
    Swal.fire({ 
        title: 'Saving...', 
        allowOutsideClick: false, 
        didOpen: () => { Swal.showLoading(); } 
    });
    
    form.submit();
}

function showAddSourceModal(submitUrl) {
    // URL can be passed explicitly or retrieved from global config
    const actionUrl = submitUrl || (window.AppConfig ? window.AppConfig.urls.addSource : '/system/add_source');

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
            <div class="row g-2 mb-2">
                <div class="col-6 text-start"><label class="small fw-bold">Auth Username</label><input type="text" id="srcAuthUser" class="form-control" placeholder="Optional"></div>
                <div class="col-6 text-start"><label class="small fw-bold">Auth Password</label><input type="password" id="srcAuthPass" class="form-control" placeholder="Optional"></div>
            </div>
            <div class="text-start"><label class="small fw-bold">Confidence (0-100)</label><input type="number" id="srcConf" class="form-control" value="50" min="0" max="100"></div>
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
                auth_pass: document.getElementById('srcAuthPass').value,
                confidence: document.getElementById('srcConf').value
            };
        }
    }).then(result => { if (result.isConfirmed) submitForm(actionUrl, result.value); });
}

function showEditSourceModal(index, source, submitUrlBase) {
    const actionUrl = (submitUrlBase || '/system/update_source/') + index;

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
    }).then(res => { if (res.isConfirmed) submitForm(actionUrl, res.value); });
}

function showSavingAlert() { 
    Swal.fire({ 
        title: 'Saving...', 
        allowOutsideClick: false, 
        didOpen: () => { Swal.showLoading(); } 
    }); 
}

// Make functions globally available
window.showAddSourceModal = showAddSourceModal;
window.showEditSourceModal = showEditSourceModal;
window.submitForm = submitForm;
window.showSavingAlert = showSavingAlert;
