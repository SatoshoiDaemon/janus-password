// Unlock state is UI state only. The server checks the key/session on every call.
let vaultUnlocked = false;
let vaultTimeout = 300;
let vaultLastActivity = Date.now();
let vaultEpoch = 0;
let clipboardTimer;

function clearVaultUI() {
    vaultUnlocked = false;
    vaultEpoch++;
    closeCredentialModal();
    closeViewCredentialModal();
    closeNoteModal();
    closeViewNoteModal();
    ['unlockForm', 'restoreForm', 'changeMasterForm'].forEach(id => document.getElementById(id).reset());
    document.getElementById('changeMasterForm').hidden = true;
    document.getElementById('restoreDetails').open = false;
    document.getElementById('generatedPassword').textContent = 'ainda não há uma senha gerada';
    document.getElementById('credentialsList').textContent = 'Desbloqueie o cofre para ver suas credenciais.';
    document.getElementById('notesList').textContent = 'Desbloqueie o cofre para ver suas notas.';
    document.getElementById('vaultStatus').textContent = 'Cofre bloqueado. Sua sessão de login continua ativa.';
    document.getElementById('unlockForm').hidden = false;
}

async function vaultRequest(path, data) {
    const buttons = document.querySelectorAll('#vault button[type="submit"], #exportVaultBtn');
    buttons.forEach(button => button.disabled = true);
    try {
    const response = await fetch('/api/vault/' + path, {
        method: 'POST', headers: {'Content-Type': 'application/json'},
        body: JSON.stringify(data || {})
    });
    const result = await response.json();
    if (!response.ok) throw new Error(result.error || 'Operação não concluída.');
    return result;
    } finally { buttons.forEach(button => button.disabled = false); }
}

async function refreshVaultStatus() {
    const epoch = vaultEpoch;
    const response = await fetch('/api/vault/status');
    if (!response.ok) return;
    const data = await response.json();
    if (epoch !== vaultEpoch) return;
    vaultTimeout = data.timeout;
    document.getElementById('masterConfirmGroup').hidden = data.configured;
    document.getElementById('vaultMasterConfirm').required = !data.configured;
    if (!data.unlocked) {
        // Preserve password/file inputs while the user completes a locked-vault
        // form; polling should only scrub when unlock state actually changes.
        if (vaultUnlocked) clearVaultUI();
        if (!data.configured) document.getElementById('vaultStatus').textContent = 'Configure o cofre definindo a senha mestra. Cofres existentes serão migrados sem apagar dados.';
        return;
    }
    vaultUnlocked = true;
    document.getElementById('vaultStatus').textContent = `Cofre desbloqueado. Bloqueio após ${vaultTimeout} segundos sem uso do cofre.`;
    document.getElementById('unlockForm').hidden = true;
}

async function lockVault() {
    clearVaultUI(); // Clear visible secrets even if the server is unreachable.
    try { await vaultRequest('lock'); }
    catch (error) { showMessage(error.message, 'error'); }
}

document.addEventListener('DOMContentLoaded', () => {
    clearVaultUI();
    refreshVaultStatus().then(() => { if (vaultUnlocked) { loadCredentials(); loadNotes(); } });
    document.getElementById('unlockForm').addEventListener('submit', async event => {
        event.preventDefault();
        const field = document.getElementById('vaultMasterPassword');
        const password = field.value;
        if (!document.getElementById('masterConfirmGroup').hidden && password !== document.getElementById('vaultMasterConfirm').value) {
            showMessage('A confirmação da senha mestra não confere.', 'error'); return;
        }
        field.value = '';
        document.getElementById('vaultMasterConfirm').value = '';
        const epoch = vaultEpoch;
        try {
            await vaultRequest('unlock', {master_password: password});
            if (epoch !== vaultEpoch) { await vaultRequest('lock'); return; }
            vaultLastActivity = Date.now();
            await refreshVaultStatus();
            loadCredentials(); loadNotes();
        } catch (error) { showMessage(error.message, 'error'); }
    });
    document.getElementById('lockVaultBtn').addEventListener('click', lockVault);
    document.getElementById('exportVaultBtn').addEventListener('click', async () => {
        try {
            const backup = await vaultRequest('export');
            const url = URL.createObjectURL(new Blob([JSON.stringify(backup)], {type: 'application/json'}));
            const link = document.createElement('a');
            link.href = url; link.download = `janus-${new Date().toISOString().slice(0, 10)}.janus`;
            link.click();
            setTimeout(() => URL.revokeObjectURL(url), 1000);
        } catch (error) { showMessage(error.message, 'error'); }
    });
    document.getElementById('restoreForm').addEventListener('submit', async event => {
        event.preventDefault();
        const field = document.getElementById('backupMasterPassword');
        const password = field.value; field.value = '';
        const file = document.getElementById('backupFile').files[0];
        if (!file || file.size > 16 * 1024 * 1024) { showMessage('Selecione um backup de até 16 MiB.', 'error'); return; }
        try {
            const result = await vaultRequest('restore', {backup: JSON.parse(await file.text()), master_password: password});
            clearVaultUI();
            showMessage(result.message, 'success');
        } catch (error) { showMessage(error.message, 'error'); }
    });
    document.getElementById('changeMasterBtn').addEventListener('click', () => {
        document.getElementById('changeMasterForm').hidden = false;
        document.getElementById('currentMaster').focus();
    });
    document.getElementById('changeMasterForm').addEventListener('submit', async event => {
        event.preventDefault();
        const current = document.getElementById('currentMaster').value;
        const next = document.getElementById('newMaster').value;
        if (next !== document.getElementById('confirmMaster').value) { showMessage('As senhas não conferem.', 'error'); return; }
        event.target.reset();
        try {
            const result = await vaultRequest('change-password', {current_password: current, new_password: next});
            clearVaultUI();
            showMessage(result.message, 'success');
        } catch (error) { showMessage(error.message, 'error'); }
    });
    // Polling does not extend server unlock lifetime; it also notices locks in
    // other tabs and process restarts. Browser input alone cannot keep keys alive.
    setInterval(() => {
        if (vaultUnlocked && Date.now() - vaultLastActivity >= vaultTimeout * 1000) lockVault();
        else refreshVaultStatus().catch(() => clearVaultUI());
    }, 5000);
    ['pointerdown', 'keydown'].forEach(name => document.addEventListener(name, () => { vaultLastActivity = Date.now(); }));
    document.addEventListener('keydown', event => {
        if (event.key === 'Escape') { closeCredentialModal(); closeViewCredentialModal(); closeNoteModal(); closeViewNoteModal(); }
        if (event.ctrlKey && event.shiftKey && event.key.toLowerCase() === 'l') { event.preventDefault(); lockVault(); }
    });
    window.addEventListener('pagehide', () => {
        clearVaultUI();
        // keepalive allows the lock request to finish when navigating away.
        if (csrfToken) nativeFetch('/api/vault/lock', {method: 'POST', headers: {'X-CSRF-Token': csrfToken}, keepalive: true}).catch(() => {});
    });
    window.addEventListener('pageshow', event => { if (event.persisted) { clearVaultUI(); refreshVaultStatus(); } });
});

// Best-effort clipboard clearing: browsers may deny background clipboard reads.
// Never erase text copied by another application after the Janus copy.
const originalCopyToClipboard = copyToClipboard;
copyToClipboard = async function(text) {
    if (!navigator.clipboard) { originalCopyToClipboard(text); return; }
    try {
        await navigator.clipboard.writeText(text);
        clearTimeout(clipboardTimer);
        clipboardTimer = setTimeout(async () => {
            try { if (await navigator.clipboard.readText() === text) await navigator.clipboard.writeText(''); }
            catch (_) { /* Clipboard permission is controlled by the browser. */ }
        }, 30000);
    } catch (_) { showMessage('O navegador não permitiu copiar.', 'error'); }
};
