const api = globalThis.browser || chrome;

async function settings() {
    const data = await api.storage.local.get(['endpoint', 'token']);
    const url = new URL(data.endpoint || 'http://127.0.0.1:5000');
    if (url.protocol !== 'http:' || url.hostname !== '127.0.0.1' || url.username || url.password || url.pathname !== '/') throw new Error('Use http://127.0.0.1:PORTA como endereço local.');
    if (!data.token) throw new Error('Pareie a extensão com o Janus primeiro.');
    return {endpoint: url.origin, token: data.token};
}
async function local(path, body) {
    const config = await settings();
    const response = await fetch(config.endpoint + '/api/browser/' + path, {
        method: 'POST', credentials: 'omit', cache: 'no-store',
        headers: {'Content-Type':'application/json', 'Authorization':'Bearer '+config.token, 'X-Janus-Extension-Origin':(new URL(api.runtime.getURL('/')).protocol+'//'+new URL(api.runtime.getURL('/')).host)},
        body: JSON.stringify(body || {})
    });
    const result = await response.json();
    if (!response.ok) throw new Error(result.error || 'Janus indisponível.');
    return result;
}
async function active() {
    const [tab] = await api.tabs.query({active:true, currentWindow:true});
    const url = new URL(tab.url);
    if (!['https:', 'http:'].includes(url.protocol)) throw new Error('Abra uma página HTTP ou HTTPS.');
    return {id: tab.id, origin: url.origin};
}
// Runs only after a popup action, in the top frame, with fresh origin validation.
function formAction(expected, fill) {
    if (window.top !== window || location.origin !== expected) throw new Error('A página mudou; tente novamente.');
    const visible = element => !element.disabled && !element.readOnly && element.getClientRects().length;
    const passwords = [...document.querySelectorAll('input[type="password"]')].filter(visible);
    if (passwords.length !== 1) throw new Error('Selecione uma página com um único campo de senha visível.');
    const password = passwords[0];
    const form = password.form;
    if (form && new URL(form.action || location.href, location.href).origin !== expected) throw new Error('O formulário envia para outro domínio. Preenchimento bloqueado.');
    const scope = form || document;
    const login = [...scope.querySelectorAll('input')].find(element => visible(element) && ['email','text'].includes(element.type) && !['search'].includes(element.autocomplete));
    if (!fill) return {login:login?.value || '', password:password.value};
    const set = (element, value) => {
        if (!element) return;
        Object.getOwnPropertyDescriptor(HTMLInputElement.prototype,'value').set.call(element,value);
        element.dispatchEvent(new Event('input',{bubbles:true}));
        element.dispatchEvent(new Event('change',{bubbles:true}));
    };
    set(login,fill.login); set(password,fill.password);
    return {filled:true}; // Never submit the form.
}
async function act(message) {
    if (message.action === 'generate') return local('generate');
    const tab = await active();
    if (message.action === 'matches') return local('matches',{url:tab.origin});
    if (message.action === 'fill') {
        const secret = await local('reveal',{url:tab.origin,id:message.id});
        const latest = await active();
        if (latest.id !== tab.id || latest.origin !== tab.origin) throw new Error('A aba mudou; tente novamente.');
        const result = await api.scripting.executeScript({target:{tabId:tab.id,frameIds:[0]},func:formAction,args:[tab.origin,secret]});
        if (!result[0]?.result?.filled) throw new Error('Não foi possível preencher este formulário.');
        secret.password = ''; return {filled:true};
    }
    if (message.action === 'capture') {
        const result = await api.scripting.executeScript({target:{tabId:tab.id,frameIds:[0]},func:formAction,args:[tab.origin,null]});
        if (!result[0]?.result) throw new Error('Não foi possível ler o formulário.');
        return {...result[0].result,url:tab.origin};
    }
    if (message.action === 'save') {
        if (tab.origin !== message.url) throw new Error('A página mudou desde a captura.');
        return local('capture',{url:tab.origin,name:message.name,login:message.login,password:message.password});
    }
    throw new Error('Ação desconhecida.');
}
api.runtime.onMessage.addListener((message,sender,respond) => {
    if (sender.id !== api.runtime.id || sender.url !== api.runtime.getURL('popup.html')) return false;
    act(message).then(value=>respond({ok:true,value})).catch(error=>respond({ok:false,error:error.message}));
    return true;
});
