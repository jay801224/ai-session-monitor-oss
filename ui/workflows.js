'use strict';
const $ = id => document.getElementById(id);
const selectedHost = new URLSearchParams(location.search).get('host') || 'local';
let hostIdentity = null, hostReady = false;
const scopedStorage = key => key + '@' + selectedHost;
const token = new URLSearchParams(location.search).get('token') || '';
const labels = {
  plan:'Plan 準備',plan_review:'Plan 審查',implement:'實作',pr_review:'PR 審查',
  integrate:'驗證與整合',ready_merge:'A 已決定可合併',succeeded:'執行完成，待主責判斷',
  failed:'執行失敗',queued:'已排隊',reconciled:'已人工核對',confirmed:'已確認送達',
  not_sent:'尚未送出',inflight_or_unknown:'執行中或結果待核對',needs_reconcile:'需要核對',
  merged:'已合併',cancelled:'已取消',running:'原生執行中',starting:'正在啟動',
  completed:'原生執行結束',stop_requested:'已要求停止，等待確認',unknown:'結果不明，需核對',
  stopped:'已停止',waiting:'等待前一個工作',submitted:'已排入 Dispatch',blocked:'等待處理'
};
let works = [], routes = {}, selected = null, signature = '', eventCursor = 0, eventWork = null;
let pending = null, refreshing = false, loadingEvents = false;
let executionFacts = {};
try { pending = JSON.parse(sessionStorage.getItem(scopedStorage('workflow-request')) || 'null'); } catch { /* Preserve usable UI after corrupt browser storage. */ }
if(pending?.expected_instance_id)hostIdentity=pending.expected_instance_id;
$('back').href = '/?token=' + encodeURIComponent(token);
function name(vendor) { return vendor === 'claude' || vendor === 'cc' ? 'Claude Code' : vendor === 'codex' ? 'Codex' : vendor; }
function routeName(route) { return name(routes[route]?.vendor || route); }
function node(tag, text, cls) { const el=document.createElement(tag); if(text !== undefined)el.textContent=text; if(cls)el.className=cls; return el; }
function error(err) { $('error').className='error'; $('error').textContent=err.message || String(err); }
function pendingControls() { $('dispatchHost').disabled=!!pending; $('retry').hidden=!pending; $('resolve').hidden=!pending; }
function option(select, value, text) { const o=node('option',text); o.value=value; select.append(o); }
async function api(path, body) {
  if(path.startsWith('/api/workflows') && path!=='/api/workflows/hosts') {
    const url=new URL(path,location.origin);url.searchParams.set('host',selectedHost);
    if(hostIdentity)url.searchParams.set('expected_instance_id',hostIdentity);path=url.pathname+url.search;
  }
  if(body)body={host:selectedHost,expected_instance_id:hostIdentity,...body};
  const response=await fetch(path, {method:body?'POST':'GET',headers:{'X-Token':token,
    ...(body?{'Content-Type':'application/json','X-CSRF-Token':'__CSRF__'}:{})},body:body?JSON.stringify(body):undefined});
  let data;
  try { data=await response.json(); } catch { throw Error('服務未回傳有效結果。請保留原請求識別碼，核對後再重送。'); }
  if(!response.ok || !data.ok)throw Error(data.error || '操作未完成');
  return data;
}
async function send(payload) {
  payload={host:selectedHost,expected_instance_id:hostIdentity,...payload};
  pending=payload; sessionStorage.setItem(scopedStorage('workflow-request'),JSON.stringify(payload)); pendingControls();
  $('error').textContent='';
  try {
    const data=await api('/api/ops/workflow',payload);
    pending=null; sessionStorage.removeItem(scopedStorage('workflow-request')); pendingControls();
    selected=data.result.id;
    if(payload.op==='create')$('createDialog').close();
    signature=''; await refresh(); return true;
  } catch(err) { error(err); return false; }
}
function current() { return works.find(work=>work.id===selected); }
function choose(id) {
  if(selected)sessionStorage.setItem(scopedStorage('workflow-draft-')+selected,$('supplement').value);
  selected=id; sessionStorage.setItem(scopedStorage('workflow-selected'),id);
  $('supplement').value=sessionStorage.getItem(scopedStorage('workflow-draft-')+id) || '';
  signature=''; render(); loadEvents();
}
let modelRefreshBusy=false, executionSupported=false;
function modelFormReady() {
  const selectedModels=['roleA','roleB','roleC'].every(id=>$(id).value && !$(id).selectedOptions[0]?.disabled);
  $('create').querySelector('button.primary').disabled=modelRefreshBusy || !executionSupported || !hostReady || !selectedModels;
}
async function loadModelRoutes() {
  const data=await api('/api/workflows/catalog');routes=data.result.routes;
  executionSupported=data.result.execution_supported && data.result.capabilities?.fresh_baseline;
  for(const id of ['roleA','roleB','roleC','route']) {
    const before=$(id).value, previousLabel=$(id).selectedOptions[0]?.textContent;
    $(id).replaceChildren();option($(id),'','請選擇模型');
    for(const [key,route] of Object.entries(routes)) {
      if(!route.model_choice)continue;
      const native=route.runtime==='native' && (data.result.capabilities?.native_vendors || []).includes(route.vendor);
      const note=route.unavailable_reason==='subscription_coverage_unverified'?'需確認訂閱涵蓋範圍':!route.enabled?'清單過期或不可用':route.balanced?'均衡型':'';
      option($(id),key,`${name(route.vendor)} · ${route.model_name} · ${route.model}${note?'（'+note+'）':''}`);
      $(id).lastElementChild.disabled=!route.enabled || !native;
    }
    if(before) {
      if(!routes[before]?.model_choice){option($(id),before,(previousLabel || before)+'（原選擇已失效，請重新選擇）');$(id).lastElementChild.disabled=true;}
      $(id).value=before;
    } else if(id!=='route') {
      const vendor=id==='roleA'?'claude':'codex';
      const balanced=Object.entries(routes).filter(([,r])=>r.model_choice && r.vendor===vendor && r.enabled && r.balanced);
      $(id).value=balanced.length===1?balanced[0][0]:'';
    }
  }
  if(!$('repo').options.length)for(const repo of data.repositories || [])option($('repo'),repo,repo);
  signature='';modelFormReady();render();
}
async function refreshModels() {
  if(modelRefreshBusy)return;
  modelRefreshBusy=true;$('refreshModels').disabled=true;modelFormReady();
  $('modelCatalogStatus').textContent='查詢本機 agent 與帳號可用模型中；不會送出工作提示…';
  const notes=[];
  try {
    for(const vendor of ['claude','codex']) {
      try {
        const result=(await api('/api/ops/workflow',{schema:1,op:'models',refresh:true,vendor})).result;
        const entry=result.providers[vendor];
        notes.push(`${name(vendor)}：${entry.error?'查詢失敗，舊清單不可選':entry.version+' · '+entry.models.length+' 款 · '+new Date(entry.checked_at).toLocaleTimeString()}`);
      } catch(error) {notes.push(name(vendor)+'：'+error.message);}
    }
    await loadModelRoutes();
  } catch(error) {notes.push(error.message);}
  finally {modelRefreshBusy=false;$('refreshModels').disabled=false;$('modelCatalogStatus').textContent=notes.join('；');modelFormReady();}
}
async function inspectHost() {
  hostReady=false;modelFormReady();
  try {
    const value=(await api('/api/workflows/capabilities')).result;
    $('hostContext').textContent=value.hostname+' · '+value.platform;
    hostIdentity=value.instance_id;hostReady=value.execution_supported===true && value.runtimes?.native?.supported===true;
    const providerNotes=Object.entries(value.providers).map(([vendor,p])=>`${name(vendor)}：${!p.installed?'未安裝':p.authenticated===true?'訂閱已登入':p.authenticated===false?'尚未登入':'登入狀態不明'}`);
    $('hostStatus').textContent=`${value.hostname} · ${value.platform} · ${hostReady?'支援執行隔離':'目前不支援改檔隔離，禁止派工'}。${providerNotes.join('；')}。這是能力檢查，並非實機派工驗收。`;
  } catch(err) {$('hostStatus').textContent='主機不可用：'+err.message;}
  modelFormReady();
}
$('inspectHost').onclick=async()=>{await inspectHost();await refreshModels();};
$('dispatchHost').onchange=()=>{if(pending)return;const url=new URL(location.href);url.searchParams.set('host',$('dispatchHost').value);location.href=url.href;};
async function init() {
  const hosts=(await api('/api/workflows/hosts')).result;
  $('dispatchHost').replaceChildren();option($('dispatchHost'),'','請選擇主機');
  for(const host of hosts)option($('dispatchHost'),host.id,host.label+(host.remote?'（遠端 Dispatch）':'（本機 Dispatch）'));
  if(!hosts.some(h=>h.id===selectedHost)){$('hostStatus').textContent='請先選擇已設定的執行主機';modelFormReady();return;}
  $('dispatchHost').value=selectedHost;pendingControls();
  await inspectHost();
  selected=sessionStorage.getItem(scopedStorage('workflow-selected'));
  await refresh();
  if(selected)$('supplement').value=sessionStorage.getItem(scopedStorage('workflow-draft-')+selected) || '';
  await refreshModels();
}
$('refreshModels').onclick=refreshModels;
for(const id of ['roleA','roleB','roleC'])$(id).onchange=modelFormReady;
async function refresh() {
  if(refreshing || !hostIdentity)return;
  refreshing=true;
  try {
    works=(await api('/api/workflows')).result;
    if(!selected && works.length)selected=works[0].id;
    $('jobs').replaceChildren();
    if(!works.length)$('jobs').append(node('p','尚無工作','muted'));
    for(const work of works) {
      const button=node('button',undefined,work.id===selected?'selected':'');
      button.append(node('strong',work.requirements.split('\n')[0].slice(0,48)),
        node('small',`${labels[work.phase] || work.phase}${work.blocked?' · 等你決定':''}`));
      button.onclick=()=>choose(work.id); $('jobs').append(button);
    }
    render(); await loadEvents();
  } catch(err) { error(err); } finally { refreshing=false; }
}
function render() {
  const work=current(); $('empty').hidden=!!work; $('detail').hidden=!work;
  if(!work)return;
  const next=JSON.stringify(work);
  if(signature===next)return;
  signature=next;
  const open=new Set(Array.from($('attempts').querySelectorAll('details[open]')).map(el=>el.dataset.key));
  $('title').textContent=work.requirements.split('\n')[0].slice(0,80);
  $('project').textContent=work.source.split(/[\\/]/).pop()+' ／ '+work.id;
  $('phase').textContent=labels[work.phase] || work.phase;
  $('meta').textContent=`版本 ${work.revision} · ${work.active?'有工作排隊或執行中':'等待下一步'}`;
  $('brief').textContent=work.requirements;
  $('workpath').textContent=work.worktree;
  $('changed').textContent='待提交：'+((work.changed_files || []).join(', ') || '無');
  $('prlink').hidden=!/^https:\/\/github\.com\//.test(work.pr_url || '');
  if(!$('prlink').hidden)$('prlink').href=work.pr_url;
  $('blocked').replaceChildren();
  if(work.blocked)$('blocked').append(node('p',`等待你的決定：${labels[work.blocked.gate] || work.blocked.gate}。${work.blocked.reason}。${work.blocked.gate==='model_selection'?'模型未被替換；可先取消尚未送出的執行，再重新選擇。':'可在右側選擇等待、改派或只略過此關。'}`,'notice'));
  $('roles').replaceChildren();
  for(const [role,route] of Object.entries(work.roles)) {
    const vendor=routes[route]?.vendor || route;
    const person=node('div',undefined,'person provider-'+vendor);
    person.append(node('strong',routeName(route)),node('small',role+' · '+({A:'主責／實作',B:'Plan 審查',C:'PR 審查'}[role])),
      node('small',routes[route]?.model || work.attempts.findLast(a=>a.route===route)?.requested_model || '原模型選項已失效，請核對執行紀錄'));
    $('roles').append(person);
  }
  $('attempts').replaceChildren();
  for(const attempt of work.attempts) {
    const vendor=attempt.vendor || routes[attempt.route]?.vendor || attempt.route;
    const card=node('article',undefined,'message provider-'+vendor);
    const head=node('div',undefined,'message-head');
    head.append(node('span','', 'provider-dot'),node('strong',`${attempt.sender==='user'?'你':'Dispatch'} → ${name(vendor)}`),
      node('small','角色 '+attempt.role),node('span',labels[attempt.status] || attempt.status,'badge'));
    const flow=node('div',undefined,'execution-flow');flow.dataset.job=attempt.id;
    renderExecutionFlow(flow,attempt,executionFacts[attempt.id]);
    card.append(flow);
    card.append(head,node('p',(labels[attempt.delivery] || attempt.delivery || '尚無送達證據')+' · '+(attempt.runtime==='native'?'原生執行':'批次執行'),'delivery'));
    const dispatched=node('details'); dispatched.dataset.key=attempt.id+'-prompt'; dispatched.open=open.has(dispatched.dataset.key);
    dispatched.append(node('summary','完整送出內容'),node('pre',attempt.prompt || '此舊版 Dispatch 未提供完整送出內容'));
    card.append(dispatched,node('pre',attempt.report || '尚無完整回覆；執行狀態以原始回報為準。','reply'));
    const facts=node('details'); facts.dataset.key=attempt.id+'-facts'; facts.open=open.has(facts.dataset.key);
    facts.append(node('summary','版本、模型與檔案變更'),node('pre',`工作：${attempt.id}\n模型：${attempt.observed_model || '尚未觀測'}\n送審 SHA：${attempt.sha || '實作中'}\n變更：${(attempt.changed_files || []).join(', ') || '尚無改檔證據'}`));
    card.append(facts); $('attempts').append(card);
  }
  $('messages').replaceChildren();
  for(const message of work.messages || []) {
    if(message.state==='submitted')continue;
    const card=node('article',undefined,'message message-pending');
    card.append(node('strong',`你 → ${routeName(message.recipient)}`),node('p',`${message.mode==='immediate'?'立即補充':'完成後排隊'} · ${labels[message.state] || message.state}${message.reason?' · '+message.reason:''}`,'delivery'),node('pre',message.text,'reply'));
    $('messages').append(card);
  }
  $('decisions').textContent=JSON.stringify(work.decisions,null,2);
  $('sha').placeholder=work.head;
  for(const opt of $('action').options)opt.disabled=!(work.allowed_actions || []).includes(opt.value);
  if($('action').selectedOptions[0]?.disabled)$('action').value=(work.allowed_actions || []).find(v=>v!=='followup') || '';
  fields();
  $('actionForm').querySelector('button').disabled=!$('action').value;
  const active=work.attempts.find(attempt=>attempt.id===work.active);
  const recipient=active?.route || work.roles.A;
  $('recipient').textContent='補充給 '+routeName(recipient);
  $('compose').className='composer provider-'+(routes[recipient]?.vendor || recipient);
  const canFollow=(work.allowed_actions || []).includes('followup');
  const canEdit=(work.allowed_actions || []).includes('edit');
  $('sendMessage').disabled=!(canFollow || canEdit);
  $('sendMode').disabled=!canFollow;
  $('inputState').textContent=canFollow?'選擇立即或排隊':canEdit?'送入下一次執行':'請使用右側流程操作';
}
function fields() { for(const el of document.querySelectorAll('[data-fields]'))el.hidden=!el.dataset.fields.split(' ').includes($('action').value); }
function renderQuestions(workId, questions) {
  const host=$('operatorQuestions');
  for (const record of questions) {
    const identity=JSON.stringify([record.job_id,record.key]);
    let card=Array.from(host.children).find(el=>el.dataset.identity===identity);
    const signature=JSON.stringify([record.state,record.execution_state,record.response]);
    if(card?.dataset.signature===signature)continue;
    if(!card){card=node('article',undefined,'message provider-codex');card.dataset.identity=identity;host.append(card);}
    card.dataset.signature=signature; card.replaceChildren();
    const active=record.state==='pending' && record.execution_state==='running';
    const status={pending:active?'等待你回答；不會自動選擇':'原執行已停止或待核對，保留問題',answered:'答案已記錄，等待送出',sending:'答案正在送出或送出結果待核對',sent:'答案已寫入原生通道；不代表工作完成'};
    card.append(node('strong','Codex → 你'),node('p',status[record.state] || record.state,'delivery'));
    const form=node('form'), fields=[], draftKey=scopedStorage('native-question-')+workId+'-'+identity;
    const draft=JSON.parse(sessionStorage.getItem(draftKey) || '{}');
    for (const question of record.request.params.questions) {
      const field=node('fieldset'), legend=node('legend',question.question);
      field.append(legend);
      const choices=[];
      for(const option of question.options || []) {
        const label=node('label'), radio=node('input');radio.type='radio';radio.name=question.id;
        radio.value=option.label;radio.checked=draft[question.id]?.choice===option.label;
        radio.disabled=!active; choices.push(radio);
        label.append(radio,document.createTextNode(option.label+' — '+option.description));field.append(label);
      }
      const label=node('label','自行回答或補充'), text=node('textarea');
      text.value=record.response?.answers?.[question.id]?.answers?.join('\n') || draft[question.id]?.text || '';
      text.disabled=!active;label.append(text);field.append(label);form.append(field);
      fields.push({id:question.id,choices,text});
    }
    form.oninput=()=>sessionStorage.setItem(draftKey,JSON.stringify(Object.fromEntries(fields.map(f=>[f.id,{text:f.text.value,choice:f.choices.find(c=>c.checked)?.value}]))));
    const button=node('button','送出這次回答','primary'), problem=node('p',undefined,'error');
    button.type='submit';button.disabled=!active;form.append(button,problem);
    form.onsubmit=async event=>{
      event.preventDefault();button.disabled=true;problem.textContent='';
      try {
        const answers={};
        for(const f of fields){const text=f.text.value.trim() || f.choices.find(c=>c.checked)?.value;
          if(!text)throw Error('請回答每一題，系統不會代選。');answers[f.id]={answers:[text]};}
        await api('/api/ops/workflow',{schema:1,op:'answer_question',id:workId,job_id:record.job_id,
          question_key:record.key,actor:'user',response:{answers}});
        sessionStorage.removeItem(draftKey);await loadEvents();
      } catch(error){problem.textContent=error.message+'；可重送同一份答案，請勿改答以免混淆。';button.disabled=false;}
    };
    card.append(form);
  }
}
function executionSummary(attempt, execution) {
  const host=execution?.placement;
  const owner={alive:'背景執行程序存活',dead:'背景執行程序已退出',unknown:'背景執行程序狀態無法確認'}[execution?.liveness?.state] || '尚無背景程序觀測';
  return {
    origin:attempt.sender==='user'?'你':attempt.sender==='A'?'主責 A':attempt.sender || 'Dispatch',
    recipient:`${attempt.role} · ${name(attempt.vendor || routes[attempt.route]?.vendor || attempt.route)}`,
    requested:attempt.requested_model || '舊工作未指定模型',
    observed:attempt.observed_model || execution?.receipt?.model || '尚無實際模型回報',
    host:host?`${host.hostname} · ${host.platform}`:'尚無持久化執行位置證據',
    instance:host?.instance_id || '未知',session:execution?.session_id || '尚未建立',owner,
    heartbeat:execution?.heartbeat_at?new Date(execution.heartbeat_at).toLocaleString():'尚無心跳紀錄',
    progress:execution?.progress_at?new Date(execution.progress_at).toLocaleString():'尚無進度事件',
    warning:execution?.liveness?.reconciliation_needed?'需要核對；不會自動重跑或改派。':''
  };
}
function renderExecutionFlow(element, attempt, execution) {
  const value=executionSummary(attempt,execution);element.replaceChildren();
  const path=node('div',undefined,'flow-path');
  for(const [label,text] of [['發起',value.origin],['接手',value.recipient],['執行主機',value.host]]) {
    const stop=node('div',undefined,'flow-stop');stop.append(node('small',label),node('strong',text));path.append(stop);
  }
  element.append(path,node('p',`指定：${value.requested} ／ 回報：${value.observed}`,'flow-model'),
    node('p',`Session：${value.session} · Dispatch instance：${value.instance}`,'flow-identity'),
    node('p',value.owner,'flow-owner'),node('p',`最後心跳：${value.heartbeat}；最後觀測進度：${value.progress}`,'flow-time'),
    node('small','心跳與程序存活不代表工作完成；沒有新進度也不代表卡死。'));
  if(value.warning)element.append(node('p',value.warning,'notice'));
}
async function loadEvents() {
  if(!selected || loadingEvents)return;
  if(eventWork!==selected){executionFacts={};eventWork=selected;eventCursor=0;$('events').replaceChildren();$('operatorQuestions').replaceChildren();}
  const work=selected; loadingEvents=true;
  try {
    const data=(await api('/api/workflows/events?id='+encodeURIComponent(work)+'&after='+eventCursor)).result;
    if(selected!==work)return;
    for(const item of data.events || []) {
      const detail=node('details');
      detail.append(node('summary',`#${item.seq} · ${item.event.type}${item.event.event?.method?' · '+item.event.event.method:''}`),node('pre',JSON.stringify(item.event,null,2)));
      $('events').append(detail);
    }
    executionFacts=Object.fromEntries((data.executions || []).map(e=>[e.job_id,e]));
    for(const element of $('attempts').querySelectorAll('.execution-flow')) {
      const attempt=current()?.attempts.find(a=>a.id===element.dataset.job);
      if(attempt)renderExecutionFlow(element,attempt,executionFacts[element.dataset.job]);
    }
    renderQuestions(work, data.questions || []);
    eventCursor=data.next;
    const execution=(data.executions || []).at(-1);
    $('nativeState').textContent=execution?`${labels[execution.state] || execution.state} · Session ${execution.session_id || '尚未建立'}`:'尚無原生執行事件';
    $('moreEvents').hidden=(data.events || []).length<200;
  } catch(err) { if(selected===work)$('nativeState').textContent='目前無法取得原生事件：'+err.message; }
  finally { loadingEvents=false; }
}
$('newWork').onclick=$('emptyCreate').onclick=()=>{$('createDialog').showModal();refreshModels();};
$('closeCreate').onclick=()=>$('createDialog').close();
$('action').onchange=fields; $('refresh').onclick=refresh; $('moreEvents').onclick=loadEvents;
$('retry').onclick=()=>pending && send(pending);
$('resolve').onclick=()=>{pending=null;sessionStorage.removeItem(scopedStorage('workflow-request'));pendingControls();refresh();};
$('supplement').oninput=()=>selected && sessionStorage.setItem(scopedStorage('workflow-draft-')+selected,$('supplement').value);
$('create').onsubmit=event=>{
  event.preventDefault(); if(pending){error(Error('先核對或重送上次請求，避免重複建立。'));return;}
  send({schema:1,op:'create',request_id:crypto.randomUUID(),repo:$('repo').value,base:$('base').value,
    requirements:$('requirements').value,require_model_selection:true,roles:{A:$('roleA').value,B:$('roleB').value,C:$('roleC').value},
    alternatives:$('alternatives').checked?Object.entries(routes).filter(([,r])=>r.enabled && r.runtime==='native' && r.model_choice && r.balanced).map(([key])=>key):[]});
};
$('compose').onsubmit=async event=>{
  event.preventDefault(); if(pending){error(Error('上次請求尚待核對，請保留同一識別碼。'));return;}
  const work=current(), prompt=$('supplement').value.trim(); if(!work || !prompt)return;
  const follow=(work.allowed_actions || []).includes('followup');
  const result=await send({schema:1,op:'action',id:work.id,revision:work.revision,request_id:crypto.randomUUID(),
    action:follow?'followup':'edit',actor:'user',prompt,mode:$('sendMode').value});
  if(result){$('supplement').value='';sessionStorage.removeItem(scopedStorage('workflow-draft-')+work.id);}
};
$('actionForm').onsubmit=event=>{
  event.preventDefault(); if(pending){error(Error('上次請求尚待核對，請先重送同一識別碼。'));return;}
  const work=current(); if(!work)return;
  const req={schema:1,op:'action',id:work.id,revision:work.revision,request_id:crypto.randomUUID(),action:$('action').value,actor:'user',reason:$('reason').value};
  for(const key of ['prompt','message','sha','route','remaining','validation'])req[key]=$(key).value;
  req.paths=$('paths').value.split('\n').filter(Boolean);
  req.findings=$('findings').value.split('\n').filter(Boolean).map(line=>{const [disposition,finding,...reason]=line.split('|').map(s=>s.trim());return {disposition,finding,reason:reason.join('|')};});
  req.execution_stopped=$('stopped').checked; send(req);
};
for (const vendor of ['claude','codex']) {
  const state=$(vendor+'AuthState'), login=$(vendor+'Login');
  $(vendor==='claude'?'authRefresh':'codexAuthRefresh').onclick=async()=>{
    $('authError').textContent='';
    try {
      const result=(await api('/api/workflows/auth?vendor='+vendor)).result;
      state.textContent=result.authenticated ? '已登入訂閱 · 獨立設定檔' : '尚未登入訂閱';
      if(result.authenticated)await refreshModels();
    } catch(error) {$('authError').textContent=error.message;}
  };
  login.onclick=async()=>{
    login.disabled=true; $('authError').textContent='';
    try {
      await api('/api/ops/workflow',{schema:1,op:'auth_login',vendor,actor:'user'});
      state.textContent='已開啟官方登入流程；完成後按「檢查登入」。';
    } catch(error) {$('authError').textContent=error.message;}
    finally {login.disabled=false;}
  };
}
pendingControls(); fields(); init(); setInterval(refresh,3000);
