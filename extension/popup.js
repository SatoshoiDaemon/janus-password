const api=globalThis.browser||chrome;
const $=id=>document.getElementById(id);
let capturedOrigin='';
$('origin').textContent=(new URL(api.runtime.getURL('/')).protocol+'//'+new URL(api.runtime.getURL('/')).host);
async function call(message){
    document.querySelectorAll('button').forEach(button=>button.disabled=true);
    try{const result=await api.runtime.sendMessage(message);if(!result?.ok)throw new Error(result?.error||'Sem resposta da extensão.');$('status').textContent='Concluído.';return result.value;}
    catch(error){$('status').textContent=error.message;throw error;}
    finally{document.querySelectorAll('button').forEach(button=>button.disabled=false);}
}
api.storage.local.get(['endpoint']).then(data=>{$('endpoint').value=data.endpoint||'http://127.0.0.1:5000';});
$('settings').addEventListener('submit',async event=>{event.preventDefault();const url=new URL($('endpoint').value);if(url.protocol!=='http:'||url.hostname!=='127.0.0.1'||url.username||url.password||url.pathname!=='/'){$('status').textContent='Use http://127.0.0.1:PORTA.';return;}await api.storage.local.set({endpoint:url.origin,token:$('token').value});$('token').value='';$('status').textContent='Pareamento salvo neste navegador.';});
$('forget').addEventListener('click',async()=>{await api.storage.local.remove(['token']);$('status').textContent='Pareamento removido. Revogue-o também no Janus.';});
$('matches').addEventListener('click',async()=>{try{const data=await call({action:'matches'});$('results').replaceChildren();for(const item of data.credentials){const button=document.createElement('button');button.textContent=item.site_name+' · '+item.login;button.addEventListener('click',()=>call({action:'fill',id:item.id}).catch(()=>{}));$('results').append(button);}$('status').textContent=data.credentials.length?'Escolha um acesso para preencher '+data.origin:'Nenhum acesso corresponde exatamente a '+data.origin;}catch{}});
$('capture').addEventListener('click',async()=>{try{const data=await call({action:'capture'});capturedOrigin=data.url;$('name').value=new URL(data.url).hostname;$('login').value=data.login;$('password').value=data.password;$('site').textContent='Salvar apenas para '+data.url;$('save').hidden=false;}catch{}});
$('generate').addEventListener('click',async()=>{try{const data=await call({action:'generate'});$('save').hidden=false;$('password').value=data.password;$('status').textContent='Senha gerada. Capture a página para selecionar o domínio antes de salvar.';}catch{}});
$('save').addEventListener('submit',async event=>{event.preventDefault();try{await call({action:'save',url:capturedOrigin,name:$('name').value,login:$('login').value,password:$('password').value});$('save').reset();$('save').hidden=true;}catch{}});
window.addEventListener('pagehide',()=>{$('save').reset();$('token').value='';});
