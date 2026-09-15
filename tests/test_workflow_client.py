"""Workflow UI retains the existing HTTP authorization boundary."""
import json
import os
from pathlib import Path
import sys
import unittest
from unittest.mock import patch
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
import workflow_client as client
import monitor


class ClientTests(unittest.TestCase):
    def test_model_discovery_uses_configured_dispatch_even_when_remote(self):
        payload={'schema':1,'op':'models','refresh':True,'vendor':'codex'}
        with patch.object(client.subprocess,'run') as run:
            run.return_value.returncode=0;run.return_value.stdout='{"ok":true,"result":{}}'
            for remote in (False,True):
                cfg={'dispatch_workflow':{'command':['dispatch-entry'],'remote_host_paths':remote}}
                self.assertTrue(client.request(cfg,payload)['ok'])
                self.assertEqual(json.loads(run.call_args.kwargs['input']),payload)

    def test_login_refuses_remote_or_non_operator_requests(self):
        with patch.object(client.subprocess, 'run') as run:
            base = {'command': ['python', 'entry.py']}
            for config, request in [
                ({**base, 'remote_host_paths': True}, {'op': 'auth_status', 'vendor': 'claude'}),
                (base, {'op': 'auth_login', 'vendor': 'claude'}),
                (base, {'op': 'auth_login', 'vendor': 'unknown', 'actor': 'user'})]:
                self.assertFalse(client.request({'dispatch_workflow': config}, request)['ok'])
            run.assert_not_called()

    def test_login_passes_only_through_dispatch(self):
        with patch.object(client.subprocess, 'run') as run:
            run.return_value.returncode = 0
            run.return_value.stdout = '{"ok":true,"result":{"opened":true}}'
            for vendor in ('claude', 'codex'):
                for operation in ('auth_status', 'auth_login'):
                    request = {'schema': 1, 'op': operation, 'vendor': vendor, 'actor': 'user'}
                    response = client.request({'dispatch_workflow': {'command': ['dispatch-entry']}}, request)
                    self.assertTrue(response['ok'])
                    self.assertEqual(run.call_args.args[0], ['dispatch-entry'])
                    self.assertEqual(json.loads(run.call_args.kwargs['input']), request)

    def test_native_answer_requires_an_allowed_work_before_forwarding(self):
        cfg={'dispatch_workflow':{'command':['dispatch-entry'],'repositories':['/allowed']}}
        payload={'schema':1,'op':'answer_question','id':'work','job_id':'job',
                 'question_key':'77','actor':'user','response':{'answers':{'q':{'answers':['chosen']}}}}
        with patch.object(client.subprocess,'run') as run:
            run.return_value.returncode=0
            run.return_value.stdout='{"ok":true,"result":{"source":"/outside"}}'
            self.assertEqual(client.request(cfg,payload)['code'],403)
            self.assertEqual(run.call_count,1)
            self.assertEqual(json.loads(run.call_args.kwargs['input'])['op'],'get')

    def test_unconfigured_is_visible_and_does_not_launch(self):
        with patch.object(client.subprocess,'run') as run:
            self.assertEqual(client.request({}, {'op':'list'})['code'],503)
            run.assert_not_called()

    def test_repository_allowlist_is_checked_before_subprocess(self):
        cfg={'dispatch_workflow':{'command':['python','entry.py'],'repositories':['/allowed']}}
        with patch.object(client.subprocess,'run') as run:
            self.assertEqual(client.request(cfg,{'op':'create','repo':'/elsewhere'})['code'],403)
            run.assert_not_called()

    def test_subprocess_preserves_request_id_and_json_boundary(self):
        cfg={'dispatch_workflow':{'command':['python','entry.py'],'repositories':['/allowed']}}
        request={'schema':1,'op':'action','id':'one','request_id':'stable','revision':2,'action':'wait'}
        with patch.object(client.subprocess,'run') as run:
            run.return_value.returncode=0
            run.return_value.stdout='{"ok":true,"result":{"id":"one","source":"/allowed"}}'
            self.assertTrue(client.request(cfg,request)['ok'])
            self.assertEqual(json.loads(run.call_args.kwargs['input']),request)
            self.assertFalse(run.call_args.kwargs['shell'])

    def test_timeout_is_unknown_not_safe_to_resubmit_as_new(self):
        cfg={'dispatch_workflow':{'command':['python','entry.py']}}
        with patch.object(client.subprocess,'run',side_effect=client.subprocess.TimeoutExpired('cmd',1)):
            res=client.request(cfg,{'op':'list'})
        self.assertEqual(res['code'],504)
        self.assertIn('same request ID',res['error'])

    def test_prompted_legacy_launches_are_refused(self):
        with patch.object(monitor.subprocess,'Popen') as spawn:
            self.assertFalse(monitor.ops_new_session({},'/tmp',prompt='do work')['ok'])
            self.assertFalse(monitor.ops_new_codex({},'/tmp',prompt='do work')['ok'])
            self.assertFalse(monitor.ops_launch_preset({}, {})['ok'])
            spawn.assert_not_called()

    def test_remote_repository_paths_are_not_resolved_locally(self):
        cfg={'dispatch_workflow':{'command':['ssh','host','workflow-entry'],
             'remote_host_paths':True,'repositories':['/remote/project']}}
        with patch.object(client.subprocess,'run') as run, patch.object(client.os.path,'realpath',side_effect=AssertionError('local path resolution')):
            run.return_value.returncode=0
            run.return_value.stdout='{"ok":true,"result":{"id":"remote"}}'
            self.assertTrue(client.request(cfg,{'schema':1,'op':'create','repo':'/remote/project'})['ok'])
            self.assertEqual(json.loads(run.call_args.kwargs['input'])['repo'],'/remote/project')

    def test_native_events_require_the_same_repository_allowlist(self):
        cfg={'dispatch_workflow':{'command':['python','entry.py'],'repositories':['/allowed']}}
        with patch.object(client.subprocess,'run') as run:
            run.return_value.returncode=0
            run.return_value.stdout='{"ok":true,"result":{"source":"/other"}}'
            response=client.request(cfg,{'schema':1,'op':'events','id':'private','after':0})
            self.assertEqual(response['code'],403)
            self.assertEqual(run.call_count,1)
            self.assertEqual(json.loads(run.call_args.kwargs['input'])['op'],'get')

    def test_native_event_cursor_is_forwarded_without_launching_a_provider(self):
        cfg={'dispatch_workflow':{'command':['python','entry.py'],'repositories':['/allowed']}}
        with patch.object(client.subprocess,'run') as run:
            run.return_value.returncode=0
            run.return_value.stdout='{"ok":true,"result":{"source":"/allowed","events":[]}}'
            payload={'schema':1,'op':'events','id':'work','after':42}
            self.assertTrue(client.request(cfg,payload)['ok'])
            self.assertEqual(json.loads(run.call_args.kwargs['input']),payload)

if __name__=='__main__':unittest.main()
