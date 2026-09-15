"""Subprocess-only boundary to Dispatch; no scheduler or provider invocation."""
import json
import os
import subprocess
import re


def configured_hosts(cfg):
    settings=cfg.get('dispatch_workflow') or {}
    hosts=settings.get('hosts')
    if hosts is None:
        return {'local':settings}
    if not isinstance(hosts,dict) or not hosts or any(
            not isinstance(k,str) or not re.fullmatch(r'[A-Za-z0-9_-]{1,80}',k)
            or not isinstance(v,dict) for k,v in hosts.items()):
        raise ValueError('Invalid configured Dispatch hosts')
    return hosts


def host_settings(cfg, host=None):
    hosts=configured_hosts(cfg)
    if host is None and len(hosts)==1:
        host=next(iter(hosts))
    if host not in hosts:
        raise ValueError('Select a configured Dispatch host')
    return hosts[host]


def host_list(cfg):
    try:
        return {'ok':True,'code':200,'result':[
            {'id':key,'label':value.get('label',key), 'remote':bool(value.get('remote_host_paths'))}
            for key,value in configured_hosts(cfg).items()]}
    except ValueError as exc:
        return {'ok':False,'code':400,'error':str(exc)}


def request(cfg, payload):
    try:
        settings=host_settings(cfg,payload.get('host'))
    except ValueError as exc:
        return {'ok':False,'code':400,'error':str(exc)}
    explicit='host' in payload
    payload=dict(payload);payload.pop('host',None)
    expected=payload.get('expected_instance_id')
    pinned=settings.get('instance_id')
    if pinned and expected and pinned!=expected:
        return {'ok':False,'code':409,'error':'Configured Dispatch identity changed; inspect the host.'}
    if pinned:
        payload['expected_instance_id']=pinned
    if explicit and payload.get('op') in ('create','action','recover_submission','answer_question','auth_login'):
        if not payload.get('expected_instance_id'):
            return {'ok':False,'code':409,'error':'Inspect the selected host before submitting work.'}
        if payload['op']=='create':
            payload.update(require_host_capability=True,require_model_selection=True)
    argv = settings.get('command')
    canonical = (lambda p: p) if settings.get('remote_host_paths') else os.path.realpath
    if not isinstance(argv, list) or not argv or not all(isinstance(v, str) for v in argv):
        return {'ok': False, 'code': 503, 'error': 'Configure dispatch_workflow.command to enable queued work.'}
    if payload.get('op') not in ('catalog', 'capabilities', 'models', 'list', 'get', 'create', 'action', 'recover_submission', 'events', 'answer_question', 'auth_status', 'auth_login'):
        return {'ok': False, 'code': 400, 'error': 'Unsupported workflow operation'}
    if payload.get('op') in ('auth_status', 'auth_login'):
        if settings.get('remote_host_paths'):
            return {'ok': False, 'code': 409, 'error': 'Operator login currently requires a local Dispatch host.'}
        if payload.get('vendor') not in ('claude', 'codex') or (payload['op'] == 'auth_login' and payload.get('actor') != 'user'):
            return {'ok': False, 'code': 400, 'error': 'Explicit local supported-provider login action required.'}
    if payload.get('op') == 'create':
        repo = canonical(payload.get('repo') or '')
        allowed = [canonical(p) for p in settings.get('repositories', [])]
        if repo not in allowed:
            return {'ok': False, 'code': 403, 'error': 'Repository is not in the configured workflow allowlist.'}
        payload = dict(payload, repo=repo)
    if payload.get('op') in ('get', 'action', 'recover_submission', 'events', 'answer_question'):
        lookup = {'schema': 1, 'op': 'get', 'id': payload.get('id')}
        if payload.get('expected_instance_id'):
            lookup['expected_instance_id']=payload['expected_instance_id']
        try:
            check = subprocess.run(argv, input=json.dumps(lookup), capture_output=True,
                                   encoding='utf-8', timeout=30, shell=False)
            existing = json.loads(check.stdout)
            if check.returncode or not existing.get('ok'):
                raise ValueError(existing.get('error') or 'Work lookup failed')
            source = canonical(existing['result']['source'])
            allowed = [canonical(p) for p in settings.get('repositories', [])]
            if source not in allowed:
                return {'ok': False, 'code': 403, 'error': 'Work repository is outside the configured allowlist.'}
        except (OSError, ValueError, KeyError, subprocess.TimeoutExpired) as exc:
            return {'ok': False, 'code': 503, 'error': str(exc)}
    try:
        result = subprocess.run(argv, input=json.dumps(payload), capture_output=True,
                                encoding='utf-8', timeout=150, shell=False)
        doc = json.loads(result.stdout)
        if not isinstance(doc, dict) or type(doc.get('ok')) is not bool:
            raise ValueError('Invalid Dispatch response')
        if payload.get('op') == 'list' and doc.get('ok'):
            allowed = [canonical(p) for p in settings.get('repositories', [])]
            doc['result'] = [w for w in doc['result'] if canonical(w['source']) in allowed]
        doc['code'] = 200 if result.returncode == 0 and doc['ok'] else 409
        return doc
    except subprocess.TimeoutExpired:
        return {'ok': False, 'code': 504, 'error': 'Dispatch response unknown. Refresh and retry the same request ID; do not create a new request.'}
    except (OSError, ValueError) as exc:
        return {'ok': False, 'code': 503, 'error': str(exc)}
