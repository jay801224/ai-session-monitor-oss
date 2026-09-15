#!/usr/bin/env python3
"""Local HTTP -> Dispatch -> actual disk edit acceptance, with a provider double.

This is not a certification of real provider execution. No model is invoked.
"""
import argparse
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import threading
import urllib.error
import urllib.request
from http.server import ThreadingHTTPServer


def main():
    parser=argparse.ArgumentParser()
    parser.add_argument('--dispatch-root',type=Path,required=True)
    args=parser.parse_args()
    sys.path[:0]=[str(Path(__file__).resolve().parents[1]),str(args.dispatch_root/'src')]
    import monitor
    from aidispatch import workflow as w, ingress
    from aidispatch.daemon import Conductor
    with tempfile.TemporaryDirectory() as temp:
        root=Path(temp).resolve();repo=root/'repo';repo.mkdir()
        os.environ['CLI_BRIDGE_HOME']=str(root/'queue')
        for a in [('init','-b','master'),('config','user.name','Acceptance'),('config','user.email','test@example.invalid')]:w.git(repo,*a)
        (repo/'result.txt').write_text('before')
        w.git(repo,'add','result.txt');w.git(repo,'commit','-m','base')
        remote=root/'origin.git'
        w.git(root,'init','--bare',str(remote))
        w.git(repo,'remote','add','origin',str(remote))
        w.git(repo,'push','origin','master')
        cfg={'access_token':'','dispatch_workflow':{'command':[sys.executable,str(args.dispatch_root/'workflow_cli.py')],'repositories':[str(repo)]}}
        monitor.load_config=lambda:cfg
        server=ThreadingHTTPServer(('127.0.0.1',0),monitor.Handler)
        monitor.SRV_PORT=server.server_port
        thread=threading.Thread(target=server.serve_forever,daemon=True);thread.start()
        base='http://127.0.0.1:'+str(server.server_port)
        def post(payload,csrf=monitor._CSRF):
            req=urllib.request.Request(base+'/api/ops/workflow',data=json.dumps(payload).encode(),headers={
                'Content-Type':'application/json','Origin':base,'X-CSRF-Token':csrf})
            with urllib.request.urlopen(req) as response:return json.load(response)['result']
        try:
            payload={'schema':1,'op':'create','request_id':'http-acceptance','repo':str(repo),
                     'requirements':'Change result.txt to after'}
            try:post(payload,csrf='wrong')
            except urllib.error.HTTPError as e:assert e.code==403
            else:raise AssertionError('CSRF guard did not reject')
            doc=post(payload);second=post(payload)
            assert doc['id']==second['id'] and doc['active']==second['active']
            assert len(ingress.pending())==1
            def runner(argv,cwd,timeout):
                prefix=argv[:argv.index('claude')]
                run=subprocess.run(prefix+[sys.executable,'-c',
                    "from pathlib import Path; Path('result.txt').write_text('after')"],cwd=cwd,capture_output=True,text=True)
                assert run.returncode==0,run.stderr
                return 0,json.dumps({'session_id':argv[argv.index('--session-id')+1],'is_error':False,
                                     'result':'Local provider double changed result.txt.'}),''
            assert Conductor(lanes=['claude'],runner=runner,sink=lambda *a,**k:None).run_once()=={'ok':1}
            assert Path(doc['worktree'],'result.txt').read_text()=='after'
            assert (repo/'result.txt').read_text()=='before'
            with urllib.request.urlopen(base+'/api/workflows') as response:listed=json.load(response)['result']
            assert listed[0]['attempts'][0]['changed_files']==['result.txt']
            assert listed[0]['attempts'][0]['status']=='succeeded'
            print('PASS: HTTP guards, duplicate submission, one queue identity, real sandboxed file edit, and UI result response')
        finally:
            server.shutdown();server.server_close();thread.join()

if __name__=='__main__':main()
