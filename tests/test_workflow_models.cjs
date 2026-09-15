// Exercise selection logic against a minimal DOM double, without provider calls.
const assert=require('node:assert/strict');
const fs=require('node:fs');
const vm=require('node:vm');
class Select {
  constructor(){this.options=[];this.value='';}
  replaceChildren(){this.options=[];this.value='';}
  get selectedOptions(){return this.options.filter(x=>x.value===this.value);}
  get lastElementChild(){return this.options.at(-1);}
}
const elements=Object.fromEntries(['roleA','roleB','roleC','route','repo'].map(k=>[k,new Select()]));
let offered={};
const route=(vendor,balanced=true)=>({vendor,model_choice:true,model:'future-'+vendor,runtime:'native',enabled:true,balanced});
const context={routes:{},signature:'',executionSupported:false,modelFormReady(){},render(){},
  $:id=>elements[id],name:x=>x,option:(select,value,textContent)=>select.options.push({value,textContent}),
  api:async()=>({result:{routes:offered,execution_supported:true,capabilities:{fresh_baseline:true,native_vendors:['claude','codex']}},repositories:[]})};
vm.createContext(context);
const source=fs.readFileSync('ui/workflows.js','utf8');
vm.runInContext(source.slice(source.indexOf('async function loadModelRoutes()'),source.indexOf('async function refreshModels()')),context);
(async()=>{
  offered={best:{...route('codex',false),isDefault:true},cc:route('claude'),balanced:route('codex')};
  await context.loadModelRoutes();
  assert.equal(elements.roleA.value,'cc');assert.equal(elements.roleB.value,'balanced');
  elements.roleB.value='best';await context.loadModelRoutes();assert.equal(elements.roleB.value,'best');
  delete offered.best;await context.loadModelRoutes();
  assert.equal(elements.roleB.value,'best');assert.equal(elements.roleB.selectedOptions[0].disabled,true);
  elements.roleB.value='';offered.second=route('codex');await context.loadModelRoutes();
  assert.equal(elements.roleB.value,'');
  delete offered.balanced;delete offered.second;offered.top=route('codex',false);
  await context.loadModelRoutes();assert.equal(elements.roleB.value,'');
  console.log('PASS: balanced default, explicit selection retained, retired choice disabled, no ambiguous or top-tier fallback');
})().catch(error=>{console.error(error);process.exitCode=1;});
