import json
from pathlib import Path
import sys
import unittest
from unittest.mock import patch
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
import workflow_client as c


class HostTests(unittest.TestCase):
    def setUp(self):
        self.cfg={'dispatch_workflow':{'hosts':{
            'mac':{'command':['dispatch-mac'],'repositories':['/shared'],'instance_id':'mac-id'},
            'windows':{'command':['dispatch-windows'],'repositories':['/shared'],'remote_host_paths':True,'instance_id':'win-id'}}}}

    def test_missing_unknown_and_injected_host_never_launch(self):
        with patch.object(c.subprocess,'run') as run:
            for host in (None,'unknown','mac;command'):
                req={'op':'list'}
                if host is not None:req['host']=host
                self.assertFalse(c.request(self.cfg,req)['ok'])
            run.assert_not_called()

    def test_same_work_id_and_path_remain_bound_to_node_in_lookup_and_action(self):
        with patch.object(c.subprocess,'run') as run:
            run.return_value.returncode=0;run.return_value.stdout='{"ok":true,"result":{"source":"/shared"}}'
            for host,identity in [('mac','mac-id'),('windows','win-id')]:
                run.reset_mock()
                result=c.request(self.cfg,{'op':'action','id':'same-id','host':host,'expected_instance_id':identity})
                self.assertTrue(result['ok'])
                for call in run.call_args_list:
                    self.assertEqual(call.args[0],['dispatch-'+host])
                    self.assertEqual(json.loads(call.kwargs['input'])['expected_instance_id'],identity)

    def test_reconfigured_identity_rejects_pending_request_before_lookup(self):
        with patch.object(c.subprocess,'run') as run:
            self.assertEqual(c.request(self.cfg,{'op':'action','id':'same-id','host':'mac','expected_instance_id':'old-mac'})['code'],409)
            run.assert_not_called()

    def test_create_cannot_bypass_capability_checks_or_repository_allowlist(self):
        with patch.object(c.subprocess,'run') as run:
            req={'op':'create','host':'mac','expected_instance_id':'mac-id','repo':'/outside'}
            self.assertEqual(c.request(self.cfg,req)['code'],403);run.assert_not_called()
            req['repo']='/shared';req['require_host_capability']=False
            run.return_value.returncode=0;run.return_value.stdout='{"ok":true,"result":{}}'
            self.assertTrue(c.request(self.cfg,req)['ok'])
            forwarded=json.loads(run.call_args.kwargs['input'])
            self.assertTrue(forwarded['require_host_capability']);self.assertTrue(forwarded['require_model_selection'])

    def test_host_list_excludes_commands_and_pins(self):
        value=c.host_list(self.cfg)
        self.assertEqual([v['id'] for v in value['result']],['mac','windows'])
        self.assertNotIn('command',str(value));self.assertNotIn('win-id',str(value))

    def test_unpinned_host_keeps_old_identity_during_pending_lookup(self):
        self.cfg['dispatch_workflow']['hosts']['mac'].pop('instance_id')
        with patch.object(c.subprocess,'run') as run:
            run.return_value.returncode=1
            run.return_value.stdout='{"ok":false,"error":"Dispatch instance changed"}'
            result=c.request(self.cfg,{'op':'action','id':'same-id','host':'mac','expected_instance_id':'original-id'})
            self.assertFalse(result['ok']);self.assertEqual(run.call_count,1)
            self.assertEqual(json.loads(run.call_args.kwargs['input'])['expected_instance_id'],'original-id')
