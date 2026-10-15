// ==================== VARIÁVEIS GLOBAIS ====================
let currentTab = 'generator';
let currentCredentialId = null;
let currentNoteId = null;
let csrfToken = null;

const nativeFetch = window.fetch.bind(window);

async function getCsrfToken() {
    if (!csrfToken) {
        const response = await nativeFetch('/api/csrf-token');
        const data = await response.json();
        csrfToken = data.csrf_token;
    }
    return csrfToken;
}

window.fetch = async function(resource, options = {}) {
    const method = (options.method || 'GET').toUpperCase();
    const requestUrl = new URL(resource, window.location.origin);
    const unsafe = ['POST', 'PUT', 'PATCH', 'DELETE'].includes(method);

    if (unsafe && requestUrl.origin === window.location.origin) {
        const headers = new Headers(options.headers || {});
        headers.set('X-CSRF-Token', await getCsrfToken());
        options.headers = headers;
    }

    const response = await nativeFetch(resource, options);
    if (response.status === 423 && typeof clearVaultUI === 'function') clearVaultUI();
    if (response.status === 401) {
        const error = await response.clone().json().catch(() => ({}));
        if (error.code === 'authentication_required') {
            if (typeof clearVaultUI === 'function') clearVaultUI();
            window.location.href = '/login';
        }
    }
    return response;
};

// ==================== INICIALIZAÇÃO ====================
document.addEventListener('DOMContentLoaded', function() {
    initializeDashboard();
    setupEventListeners();
    displayUserInfo();
    loadCredentials();
    loadNotes();
});

// ==================== FUNÇÕES DE AUTENTICAÇÃO ====================
function displayUserInfo() {
    const userInfo = document.getElementById('userInfo');
    fetch('/api/user-info', {
        method: 'GET'
    })
    .then(response => response.ok ? response.json() : Promise.reject())
    .then(data => {
        userInfo.innerHTML = `<span class="avatar">${escapeHtml((data.username || 'U').charAt(0).toUpperCase())}</span><span><small>sessão local de</small><strong>${escapeHtml(data.username || 'Usuário local')}</strong></span>`;
    })
    .catch(() => {
        userInfo.innerHTML = '<span class="avatar">U</span><span><small>sessão local de</small><strong>Usuário local</strong></span>';
    });
}

async function logout() {
    try {
        const response = await fetch('/api/logout', {
            method: 'POST'
        });

        if (response.ok) {
            clearVaultUI();
            window.location.href = '/login';
        }
    } catch (error) {
        console.error('Erro ao fazer logout:', error);
        window.location.href = '/login';
    }
}

// ==================== SETUP DE EVENT LISTENERS ====================
function setupEventListeners() {
    // Logout
    document.getElementById('logoutBtn').addEventListener('click', logout);

    // Navigation tabs
    document.querySelectorAll('.nav-item').forEach(item => {
        item.addEventListener('click', function() {
            switchTab(this.dataset.tab);
        });
    });

    // Password Generator
    document.getElementById('generateBtn').addEventListener('click', generatePassword);
    document.getElementById('copyPasswordBtn').addEventListener('click', copyPassword);
    document.getElementById('passwordLength').addEventListener('input', updateLengthDisplay);

    // Credentials
    document.getElementById('addCredentialBtn').addEventListener('click', openAddCredentialModal);
    document.getElementById('closeCredentialModal').addEventListener('click', closeCredentialModal);
    document.getElementById('cancelCredentialBtn').addEventListener('click', closeCredentialModal);
    document.getElementById('credentialForm').addEventListener('submit', saveCredential);
    document.getElementById('generatePasswordBtn').addEventListener('click', generatePasswordForCredential);
    document.getElementById('toggleCredentialPassword').addEventListener('click', toggleCredentialPasswordVisibility);

    // View Credential
    document.getElementById('closeViewCredentialModal').addEventListener('click', closeViewCredentialModal);
    document.getElementById('closeViewCredentialBtn').addEventListener('click', closeViewCredentialModal);
    document.getElementById('toggleViewCredentialPassword').addEventListener('click', toggleViewCredentialPasswordVisibility);
    document.getElementById('copyCredentialPasswordBtn').addEventListener('click', copyCredentialPassword);
    document.getElementById('deleteCredentialBtn').addEventListener('click', deleteCredential);

    // Notes
    document.getElementById('addNoteBtn').addEventListener('click', openAddNoteModal);
    document.getElementById('closeNoteModal').addEventListener('click', closeNoteModal);
    document.getElementById('cancelNoteBtn').addEventListener('click', closeNoteModal);
    document.getElementById('noteForm').addEventListener('submit', saveNote);

    // View Note
    document.getElementById('closeViewNoteModal').addEventListener('click', closeViewNoteModal);
    document.getElementById('closeViewNoteBtn').addEventListener('click', closeViewNoteModal);
    document.getElementById('copyNoteLinkBtn').addEventListener('click', copyNoteLink);
    document.getElementById('deleteNoteBtn').addEventListener('click', deleteNote);

    // Close modals ao clicar no background
    document.querySelectorAll('.modal').forEach(modal => {
        modal.addEventListener('click', function(e) {
            if (e.target === this) {
                if (this.id === 'credentialModal') closeCredentialModal();
                if (this.id === 'viewCredentialModal') closeViewCredentialModal();
                if (this.id === 'noteModal') closeNoteModal();
                if (this.id === 'viewNoteModal') closeViewNoteModal();
            }
        });
    });
}

// ==================== FUNÇÕES DE NAVEGAÇÃO ====================
function initializeDashboard() {
    switchTab('vault');
}

function switchTab(tabName) {
    // Remover ativo de todos os tabs
    document.querySelectorAll('.tab-content').forEach(tab => {
        tab.classList.remove('active');
    });

    document.querySelectorAll('.nav-item').forEach(item => {
        item.classList.remove('active');
    });

    // Adicionar ativo ao novo tab
    const tabElement = document.getElementById(tabName);
    const navItem = document.querySelector(`[data-tab="${tabName}"]`);

    if (tabElement) {
        tabElement.classList.add('active');
    }

    if (navItem) {
        navItem.classList.add('active');
    }

    currentTab = tabName;

    // Recarregar dados quando necessário
    if (tabName === 'credentials') {
        loadCredentials();
    } else if (tabName === 'notes') {
        loadNotes();
    }
}

// ==================== GERADOR DE SENHAS ====================
function updateLengthDisplay() {
    const length = document.getElementById('passwordLength').value;
    document.getElementById('lengthValue').textContent = length;
}

async function generatePassword() {
    try {
        const length = parseInt(document.getElementById('passwordLength').value);
        const useUppercase = document.getElementById('useUppercase').checked;
        const useLowercase = document.getElementById('useLowercase').checked;
        const useDigits = document.getElementById('useDigits').checked;
        const useSpecial = document.getElementById('useSpecial').checked;

        const response = await fetch('/api/generate-password', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({
                length: length,
                use_uppercase: useUppercase,
                use_lowercase: useLowercase,
                use_digits: useDigits,
                use_special: useSpecial
            })
        });

        const data = await response.json();

        if (response.ok) {
            document.getElementById('generatedPassword').textContent = data.password;
        } else {
            showMessage('Erro ao gerar senha', 'error');
        }
    } catch (error) {
        console.error('Erro:', error);
        showMessage('Erro ao gerar senha', 'error');
    }
}

function copyPassword() {
    const password = document.getElementById('generatedPassword').textContent;
    if (password !== 'ainda não há uma senha gerada') {
        copyToClipboard(password);
        showMessage('Senha copiada!', 'success');
    }
}

async function generatePasswordForCredential() {
    try {
        const response = await fetch('/api/generate-password', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({
                length: 16,
                use_uppercase: true,
                use_lowercase: true,
                use_digits: true,
                use_special: true
            })
        });

        const data = await response.json();

        if (response.ok) {
            document.getElementById('credentialPassword').value = data.password;
        }
    } catch (error) {
        console.error('Erro:', error);
    }
}

// ==================== CREDENCIAIS ====================
function openAddCredentialModal() {
    currentCredentialId = null;
    document.getElementById('credentialModalTitle').textContent = 'Adicionar Credencial';
    document.getElementById('credentialForm').reset();
    document.getElementById('customFields').replaceChildren();
    openModal('credentialModal');
}

function closeCredentialModal() {
    closeModal('credentialModal');
    document.getElementById('credentialForm').reset();
}

function openModal(modalId) {
    document.getElementById(modalId).classList.add('active');
}

function closeModal(modalId) {
    document.getElementById(modalId).classList.remove('active');
}

async function saveCredential(e) {
    e.preventDefault();

    const site_name = document.getElementById('credentialSite').value;
    const login = document.getElementById('credentialLogin').value;
    const email = document.getElementById('credentialEmail').value;
    const password = document.getElementById('credentialPassword').value;


    try {
        const method = currentCredentialId ? 'PUT' : 'POST';
        const url = currentCredentialId ? `/api/credentials/${currentCredentialId}` : '/api/credentials';

        const response = await fetch(url, {
            method: method,
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({
                site_name: site_name,
                login: login,
                email: email,
                password: password,
                ...credentialExtraValues()
            })
        });

        const data = await response.json();

        if (response.ok) {
            showMessage(data.message, 'success');
            closeCredentialModal();
            loadCredentials();
        } else {
            showMessage(data.error || 'Erro ao salvar credencial', 'error');
        }
    } catch (error) {
        console.error('Erro:', error);
        showMessage('Erro ao salvar credencial', 'error');
    }
}

async function loadCredentials() {
    try {
        const response = await fetch('/api/credentials', {
            method: 'GET'
        });

        const data = await response.json();

        if (response.ok) {
            if (vaultUnlocked) displayCredentials(data.credentials);
        } else if (response.status !== 423) {
            showMessage(data.error || 'Não foi possível carregar as credenciais. Tente abrir a aba novamente.', 'error');
        }
    } catch (error) {
        console.error('Erro:', error);
    }
}

function displayCredentials(credentials) {
    credentialCache = credentials;
    updateCredentialFilters();
    renderCredentialResults();
}

function escapeHtml(text) {
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
}

async function viewCredential(id) {
    try {
        const response = await fetch(`/api/credentials/${id}/reveal`, {method: 'POST'});

        const data = await response.json();

        if (response.ok && vaultUnlocked) {
            currentCredentialId = id;
            document.getElementById('viewCredentialSite').textContent = data.site_name;
            document.getElementById('viewCredentialLogin').textContent = data.login || '-';
            document.getElementById('viewCredentialEmail').textContent = data.email || '-';
            document.getElementById('viewCredentialPassword').value = data.password;
            openModal('viewCredentialModal');
        } else {
            showMessage(data.error || 'Erro ao carregar credencial', 'error');
        }
    } catch (error) {
        console.error('Erro:', error);
        showMessage('Erro ao carregar credencial', 'error');
    }
}

function toggleCredentialPasswordVisibility() {
    const input = document.getElementById('credentialPassword');
    const btn = document.getElementById('toggleCredentialPassword');
    const type = input.type === 'password' ? 'text' : 'password';
    input.type = type;
    btn.textContent = type === 'password' ? '👁' : '🙈';
}

function toggleViewCredentialPasswordVisibility() {
    const input = document.getElementById('viewCredentialPassword');
    const btn = document.getElementById('toggleViewCredentialPassword');
    const isPassword = input.type === 'password';
    input.type = isPassword ? 'text' : 'password';
    btn.textContent = isPassword ? '🙈 Ocultar' : '👁️ Mostrar';
}

function copyCredentialPassword() {
    const password = document.getElementById('viewCredentialPassword').value;
    copyToClipboard(password);
    showMessage('Senha copiada!', 'success');
}

function confirmDeleteCredential(id) {
    if (confirm('Mover esta credencial para a lixeira?')) {
        currentCredentialId = id;
        deleteCredential();
    }
}

async function deleteCredential() {
    if (!currentCredentialId) return;

    try {
        const response = await fetch(`/api/credentials/${currentCredentialId}`, {
            method: 'DELETE'
        });

        const data = await response.json();

        if (response.ok) {
            showMessage('Credencial movida para a lixeira!', 'success');
            closeViewCredentialModal();
            loadCredentials();
        } else {
            showMessage(data.error || 'Erro ao deletar credencial', 'error');
        }
    } catch (error) {
        console.error('Erro:', error);
        showMessage('Erro ao deletar credencial', 'error');
    }
}

function closeViewCredentialModal() {
    closeModal('viewCredentialModal');
    document.getElementById('viewCredentialPassword').value = '';
    document.getElementById('viewCredentialPassword').type = 'password';
    currentCredentialId = null;
}

// ==================== NOTAS SEGURAS ====================
function openAddNoteModal() {
    currentNoteId = null;
    document.getElementById('noteModalTitle').textContent = 'Adicionar Nota Segura';
    document.getElementById('noteForm').reset();
    openModal('noteModal');
}

function closeNoteModal() {
    closeModal('noteModal');
    document.getElementById('noteForm').reset();
}

async function saveNote(e) {
    e.preventDefault();

    const title = document.getElementById('noteTitle').value;
    const content = document.getElementById('noteContent').value;
    const note_password = document.getElementById('notePassword').value;

    try {
        const method = currentNoteId ? 'PUT' : 'POST';
        const url = currentNoteId ? `/api/notes/${currentNoteId}` : '/api/notes';

        const response = await fetch(url, {
            method: method,
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({
                title: title,
                content: content,
                note_password: note_password
            })
        });

        const data = await response.json();

        if (response.ok) {
            showMessage(data.message, 'success');
            closeNoteModal();
            loadNotes();
        } else {
            showMessage(data.error || 'Erro ao salvar nota', 'error');
        }
    } catch (error) {
        console.error('Erro:', error);
        showMessage('Erro ao salvar nota', 'error');
    }
}

async function loadNotes() {
    try {
        const response = await fetch('/api/notes', {
            method: 'GET'
        });

        const data = await response.json();

        if (response.ok) {
            if (vaultUnlocked) displayNotes(data.notes);
        } else if (response.status !== 423) {
            showMessage(data.error || 'Não foi possível carregar as notas. Tente abrir a aba novamente.', 'error');
        }
    } catch (error) {
        console.error('Erro:', error);
    }
}

function displayNotes(notes) {
    const container = document.getElementById('notesList');

    if (notes.length === 0) {
        container.innerHTML = '<p class="empty-state">Nenhuma nota salva. Adicione uma nova!</p>';
        return;
    }

    container.innerHTML = notes.map(note => `
        <div class="note-item">
            <div class="credential-info">
                <div class="credential-name">${escapeHtml(note.title)}</div>
                <div class="credential-meta">
                    criada em ${new Date(note.created_at).toLocaleDateString('pt-BR')}
                </div>
            </div>
            <div class="item-actions">
                <button class="btn btn-secondary" onclick="viewNote(${note.id})">👁️ Ver</button>
                <button class="btn btn-danger" onclick="confirmDeleteNote(${note.id})">🗑️</button>
            </div>
        </div>
    `).join('');
}

async function viewNote(id) {
    const note_password = prompt('Digite a senha da nota para visualizar:');
    
    if (!note_password) return;

    try {
        const response = await fetch(`/api/notes/${id}/reveal`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({
                note_password: note_password
            })
        });

        const data = await response.json();

        if (response.ok && vaultUnlocked) {
            currentNoteId = id;
            document.getElementById('viewNoteTitle').textContent = data.title;
            document.getElementById('viewNoteContent').textContent = data.content;
            document.getElementById('noteAccessLink').value = `${window.location.origin}/note/${data.access_token}`;
            openModal('viewNoteModal');
        } else {
            showMessage(data.error || 'Erro ao carregar nota', 'error');
        }
    } catch (error) {
        console.error('Erro:', error);
        showMessage('Erro ao carregar nota', 'error');
    }
}

function copyNoteLink() {
    const link = document.getElementById('noteAccessLink').value;
    copyToClipboard(link);
    showMessage('Link copiado!', 'success');
}

function confirmDeleteNote(id) {
    if (confirm('Tem certeza que deseja deletar esta nota?')) {
        currentNoteId = id;
        deleteNote();
    }
}

async function deleteNote() {
    if (!currentNoteId) return;

    try {
        const response = await fetch(`/api/notes/${currentNoteId}`, {
            method: 'DELETE'
        });

        const data = await response.json();

        if (response.ok) {
            showMessage('Nota deletada!', 'success');
            closeViewNoteModal();
            loadNotes();
        } else {
            showMessage(data.error || 'Erro ao deletar nota', 'error');
        }
    } catch (error) {
        console.error('Erro:', error);
        showMessage('Erro ao deletar nota', 'error');
    }
}

function closeViewNoteModal() {
    closeModal('viewNoteModal');
    document.getElementById('viewNoteContent').textContent = '';
    document.getElementById('noteAccessLink').value = '';
    currentNoteId = null;
}

// ==================== FUNÇÕES AUXILIARES ====================
function copyToClipboard(text) {
    if (navigator.clipboard && navigator.clipboard.writeText) {
        navigator.clipboard.writeText(text);
    } else {
        // Fallback para navegadores mais antigos
        const textarea = document.createElement('textarea');
        textarea.value = text;
        document.body.appendChild(textarea);
        textarea.select();
        document.execCommand('copy');
        document.body.removeChild(textarea);
    }
}

function showMessage(message, type = 'info') {
    // Mostrar alerta visível
    const alertDiv = document.createElement('div');
    alertDiv.className = `message ${type}`;
    alertDiv.textContent = message;
    alertDiv.style.position = 'fixed';
    alertDiv.style.top = '20px';
    alertDiv.style.right = '20px';
    alertDiv.style.zIndex = '9999';
    alertDiv.style.minWidth = '300px';
    document.body.appendChild(alertDiv);

    setTimeout(() => {
        alertDiv.remove();
    }, 3000);
}
