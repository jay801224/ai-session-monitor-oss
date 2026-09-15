const assert=require('node:assert/strict'),fs=require('node:fs'),vm=require('node:vm');
const code=fs.readFileSync('ui/workflows.js','utf8');
const seen=[];
const context={selectedHost:'new-host',hostIdentity:'new-id',token:'',URL,
  location:{origin:'http://local'},fetch:async(path,options)=>{seen.push({path,options});return {ok:true,json:async()=>({ok:true,result:{}})};}};
vm.createContext(context);
vm.runInContext(code.slice(code.indexOf('async function api('),code.indexOf('async function send(')),context);
(async()=>{
 await context.api('/api/ops/workflow',{op:'action',host:'original-host',expected_instance_id:'original-id',request_id:'original-request'});
 const body=JSON.parse(seen[0].options.body);
 assert.equal(body.host,'original-host');assert.equal(body.expected_instance_id,'original-id');assert.equal(body.request_id,'original-request');
 await context.api('/api/workflows/events?id=same-id');
 const url=new URL(seen[1].path,'http://local');assert.equal(url.searchParams.get('host'),'new-host');assert.equal(url.searchParams.get('expected_instance_id'),'new-id');
 console.log('PASS: pending request target preserved; reads scoped to selected host and instance');
})().catch(error=>{console.error(error);process.exitCode=1;});
