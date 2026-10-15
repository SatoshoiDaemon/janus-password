const test=require('node:test');
const assert=require('node:assert/strict');
const fs=require('node:fs');
const vm=require('node:vm');
function context(){
 let active={id:7,url:'https://example.com/login'}, injections=[], requests=[];
 const api={storage:{local:{get:async()=>({endpoint:'http://127.0.0.1:5000',token:'x'.repeat(43)})}},tabs:{query:async()=>[active]},scripting:{executeScript:async spec=>{injections.push(spec);return [{result:{filled:true}}];}},runtime:{id:'a'.repeat(32),getURL:path=>'chrome-extension://'+'a'.repeat(32)+'/'+path.replace(/^\//,''),onMessage:{addListener(){}}}};
 const sandbox={chrome:api,URL,console,fetch:async(url,options)=>{requests.push({url,options});return {ok:true,json:async()=>({origin:'https://example.com',login:'alice',password:'secret'})};}};
 vm.createContext(sandbox);vm.runInContext(fs.readFileSync('extension/background.js','utf8'),sandbox);
 return {sandbox,api,requests,injections,setTab:value=>active=value};
}
test('bridge uses explicit extension origin, user action and top-frame injection',async()=>{
 const ctx=context();assert.equal(ctx.requests.length,0);
 await vm.runInContext("act({action:'fill',id:1})",ctx.sandbox);
 assert.equal(ctx.requests[0].options.headers['X-Janus-Extension-Origin'],'chrome-extension://'+'a'.repeat(32));
 assert.equal(ctx.requests[0].options.credentials,'omit');
 assert.deepEqual(Array.from(ctx.injections[0].target.frameIds),[0]);
 assert.equal(ctx.injections[0].target.tabId,7);
});
test('navigation while fetching a secret prevents injection',async()=>{
 const ctx=context();ctx.sandbox.fetch=async()=>{ctx.setTab({id:7,url:'https://evil.test'});return{ok:true,json:async()=>({password:'secret'})};};
 await assert.rejects(vm.runInContext("act({action:'fill',id:1})",ctx.sandbox),/aba mudou/);assert.equal(ctx.injections.length,0);
});
test('form fill rejects frames, ambiguous password fields and cross-origin actions',()=>{
 const ctx=context(),box=ctx.sandbox;
 box.location={origin:'https://example.com',href:'https://example.com/login'};
 box.window={};box.window.top={};
 assert.throws(()=>vm.runInContext("formAction('https://example.com',{})",box),/página mudou/);
 box.window.top=box.window;
 box.document={querySelectorAll:()=>[1,2].map(()=>({disabled:false,readOnly:false,getClientRects:()=>[{}]}))};
 assert.throws(()=>vm.runInContext("formAction('https://example.com',{})",box),/único campo/);
 box.document={querySelectorAll:()=>[{disabled:false,readOnly:false,getClientRects:()=>[{}],form:{action:'https://evil.test'}}]};
 assert.throws(()=>vm.runInContext("formAction('https://example.com',{})",box),/outro domínio/);
});
test('endpoint configuration cannot send pairing tokens to remote hosts',async()=>{
 const ctx=context();ctx.api.storage.local.get=async()=>({endpoint:'https://evil.test',token:'secret'});
 await assert.rejects(vm.runInContext("act({action:'generate'})",ctx.sandbox),/127.0.0.1/);assert.equal(ctx.requests.length,0);
});
