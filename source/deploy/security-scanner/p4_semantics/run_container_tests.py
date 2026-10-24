"""Hermetic Linux component tests; default Describe never calls Docker.
Copyright The MatrixHub Authors. SPDX-License-Identifier: Apache-2.0
"""
import argparse,hashlib,json,os,re,subprocess,threading,time,uuid
from pathlib import Path
PINS={'linux_p4_tests.py': 'f44a31539b719fa76b9aefe7eff5ac17d89675103318fc33038e964cb8f1f209', 'linux_ascii_tests.py': '092f556bee4290f72a62f29c107c7f64832ef29109203d98114936b1eff49e40', 'fixture_helpers.py': '7d4b785dce92d5962c6b5f57202a20aefae49f63272949f895449c676e330a1b', 'root_gap_builder.py': 'ecd23cf040ab294747df7b3d3df1c4802dbe8f4dfc76aacd5438f156eefec84e', 'scanner-baseline-5fa.py': '5fa1c563389f6b70ce16d9a7c3e60fc7c5a452ede2871a231b7e386147500c57', 'scanner-parent-19aee.py': '19aee967a7d5c8e3857b4d962423af3a036f5f72af721a98372f419804b6c5ad'}
SOURCE='7cd1be1e44b007f57a643bfbb195f4495fd97ec92df872a7cbf91dbb2e4d6e01'
OWNER='matrixhub.semantic-tests.owner'
def need(value,code):
    if not value:raise ValueError(code)
def digest(path):return hashlib.sha256(path.read_bytes()).hexdigest()
def unique(items):
    result={}
    for k,v in items:
        need(k not in result,'duplicate-json');result[k]=v
    return result

def bounded_process(argv,env,seconds,stdout_cap=131072,stderr_cap=32768):
    need(seconds>0,'operation-deadline')
    p=subprocess.Popen(argv,stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE,env=env)
    output=[bytearray(),bytearray()];overflow=threading.Event();failure=threading.Event()
    def pump(stream,index,cap):
        try:
            while True:
                block=os.read(stream.fileno(),8192)
                if not block:break
                if len(output[index])+len(block)>cap:overflow.set();break
                output[index].extend(block)
        except Exception:failure.set()
        finally:stream.close()
    threads=[threading.Thread(target=pump,args=(p.stdout,0,stdout_cap),daemon=True),threading.Thread(target=pump,args=(p.stderr,1,stderr_cap),daemon=True)]
    for t in threads:t.start()
    end=time.monotonic()+seconds
    try:
        while p.poll() is None:
            if overflow.is_set() or failure.is_set() or time.monotonic()>=end:raise ValueError('bounded-process-failed')
            time.sleep(.01)
        for t in threads:t.join(2)
        need(not any(t.is_alive() for t in threads) and not overflow.is_set() and not failure.is_set(),'bounded-output-failed')
        return p.returncode,bytes(output[0]),bytes(output[1])
    finally:
        if p.poll() is None:p.kill();p.wait(timeout=5)
        for t in threads:t.join(2)

def inspect_owned(command,cid,rid,name,image):
    need(re.fullmatch('[a-f0-9]{64}',cid),'owned-full-cid')
    fmt='{"id":{{json .Id}},"name":{{json .Name}},"image":{{json .Image}},"owner":{{json (index .Config.Labels "'+OWNER+'")}}}'
    value=json.loads(command(['inspect','--format',fmt,cid])[1],object_pairs_hook=unique)
    need(value=={'id':cid,'name':'/'+name,'image':image,'owner':rid},'owned-container-identity')
    return value

def cleanup_created(command,rid,name,image,attempted,confirmed,expected_cid=None):
    need((confirmed and attempted and type(expected_cid)is str and re.fullmatch('[a-f0-9]{64}',expected_cid)) or (not confirmed and expected_cid is None),'cleanup-confirmed-cid-context')
    if not attempted:return {'createdAttempted':False,'ownedAbsent':True}
    def selected(key):
        raw=command(['ps','-a','-q','--no-trunc','--filter',key])[1].decode().split()
        need(len(raw)<=1 and all(re.fullmatch('[a-f0-9]{64}',x) for x in raw),'cleanup-selected-cids')
        return set(raw)
    label='label='+OWNER+'='+rid;exact_name='name=^/'+name+'$'
    by_label=selected(label);by_name=selected(exact_name)
    need(by_label==by_name,'cleanup-owner-name-agreement')
    engine=command(['info','--format','{{.ID}}'])[1].decode().strip();need(0<len(engine)<=128,'cleanup-engine-health')
    if not by_label:
        need(confirmed,'create-outcome-unconfirmed')
        need(not selected('id='+expected_cid),'confirmed-container-still-exists')
        return {'createdAttempted':True,'ownedAbsent':True,'creationConfirmed':True,'confirmedId':expected_cid}
    cid=next(iter(by_label));need(not confirmed or cid==expected_cid,'cleanup-container-replaced');inspect_owned(command,cid,rid,name,image)
    command(['rm','-f',cid])
    need(not selected(label) and not selected(exact_name),'cleanup-absence')
    need(command(['info','--format','{{.ID}}'])[1].decode().strip()==engine,'cleanup-same-engine')
    return {'createdAttempted':True,'removedId':cid,'ownedAbsent':True,'creationConfirmed':confirmed}

def main(argv=None):
    p=argparse.ArgumentParser();p.add_argument('--execute',action='store_true');p.add_argument('--heavy-idle-confirmed',action='store_true');p.add_argument('--docker',type=Path);p.add_argument('--engine');p.add_argument('--image');p.add_argument('--output',type=Path);a=p.parse_args(argv)
    if not a.execute:
        print(json.dumps({'mode':'DESCRIBE','dockerCalled':False,'sourceRead':False,'fixturesGenerated':0,'scope':'STATIC_COMPONENTS_ONLY_NOT_AV_APP_OR_MODEL_ACCURACY','required':['--heavy-idle-confirmed','--docker','--engine','--image','--output']}));return 0
    need(a.heavy_idle_confirmed,'explicit-idle-confirmation')
    need(a.docker is not None and a.docker.is_file() and a.docker.is_absolute(),'explicit-local-docker-path')
    allowed={'npipe:////./pipe/dockerDesktopLinuxEngine'} if os.name=='nt' else {'unix:///var/run/docker.sock'}
    need(a.engine in allowed and a.image is not None and re.fullmatch(r'(?:sha256:[a-f0-9]{64}|[a-z0-9][a-z0-9_./:@-]{0,240})',a.image) and a.output is not None,'explicit-local-engine-image-output')
    folder=Path(__file__).resolve().parent;source=folder.parent/'scanner.py'
    need(source.is_file() and not source.is_symlink() and source.stat().st_size<1<<20 and digest(source)==SOURCE,'frozen-candidate-source')
    for name,wanted in PINS.items():
        f=folder/name;need(f.is_file() and not f.is_symlink() and f.stat().st_size<1<<20 and digest(f)==wanted,'frozen-test-source')
    for path in (folder,source.parent):need(not any(x.is_symlink() for x in (path,*path.parents)) and not any(c in str(path) for c in ',\x00\r\n'),'safe-source-mount')
    out=a.output.resolve();need(not out.exists() and not any(x.is_symlink() for x in out.parents),'fresh-output-required');out.mkdir(parents=True)
    config=out/'anonymous-docker';config.mkdir();(config/'config.json').write_text('{"auths":{}}\n',encoding='utf-8')
    env={k:v for k,v in os.environ.items() if not k.upper().startswith('DOCKER_')};prefix=[str(a.docker),'--config',str(config),'--host',a.engine]
    business_deadline=time.monotonic()+30;cleanup_deadline=business_deadline;cleaning=False
    def command(args,seconds=15,allow=False):
        code,raw,err=bounded_process(prefix+args,env,min(seconds,(cleanup_deadline if cleaning else business_deadline)-time.monotonic()))
        need(allow or code==0,'docker-command-failed');return code,raw,err
    image=command(['image','inspect','--format','{{.Id}}',a.image])[1].decode().strip();need(re.fullmatch('sha256:[a-f0-9]{64}',image),'local-image-required')
    runs=[]
    for script,baseline,count in [('linux_p4_tests.py','scanner-baseline-5fa.py',84),('linux_ascii_tests.py','scanner-parent-19aee.py',34)]:
        rid=uuid.uuid4().hex;name='matrixhub-semantics-'+rid;cid=None;attempted=False;confirmed=False;started=time.monotonic();business_deadline=started+90;cleanup_deadline=started+115;cleaning=False;record={'suite':script,'runId':rid,'status':'FAIL','cleanupSuccess':False,'fullAV':False}
        try:
            deadline=int(time.time())+80
            args=['create','--name',name,'--label',OWNER+'='+rid,'--pull','never','--network','none','--read-only','--user','65532:65532','--cap-drop','ALL','--security-opt','no-new-privileges','--memory','536870912','--memory-swap','536870912','--cpus','1','--pids-limit','64','--log-driver','none','--init','--ipc','none','--cgroupns','private','--ulimit','core=0:0','--tmpfs','/tmp:rw,noexec,nosuid,nodev,size=16777216,uid=65532,gid=65532,mode=0700']
            for host,target in [(folder,'/probe'),(folder,'/baseline'),(source.parent,'/candidate')]:args+=['--mount','type=bind,source='+str(host)+',target='+target+',readonly']
            args+=['--entrypoint','python3',image,'-I','-B','/probe/'+script,'--execute','--baseline','/baseline/'+baseline,'--candidate','/candidate/scanner.py','--deadline',str(deadline),'--root-idle-confirmed']
            if script=='linux_p4_tests.py':args+=['--candidate-sha256',SOURCE]
            attempted=True
            cid=command(args)[1].decode().strip();need(re.fullmatch('[a-f0-9]{64}',cid),'created-cid')
            inspect_owned(command,cid,rid,name,image);confirmed=True
            rc,raw,err=command(['start','-a',cid],seconds=85,allow=True);need(rc==0 and not err,'component-execution-failed')
            value=json.loads(raw,object_pairs_hook=unique)
            need(value.get('status')=='PASS' and value.get('tests')==value.get('passed')==count and value.get('candidateSHA256')==SOURCE and value.get('AVRun') is False,'component-result-failed')
            need(command(['inspect','--format','{{.State.ExitCode}}',cid])[1].decode().strip()=='0','container-exit-failed')
            record.update(status='PASS',result=value)
        except Exception as e:record['failureType']=type(e).__name__
        finally:
            cleaning=True
            try:
                record['cleanup']=cleanup_created(command,rid,name,image,attempted,confirmed,cid if confirmed else None)
                record['cleanupSuccess']=True
            except Exception:
                record['status']='FAIL';record['cleanupSuccess']=False
            if time.monotonic()>cleanup_deadline:record['status']='FAIL'
            record['wholeSeconds']=time.monotonic()-started;runs.append(record)
            (out/(rid+'.json')).write_text(json.dumps(record,sort_keys=True,indent=2)+'\n',encoding='utf-8')
        if record['status']!='PASS':break
    result={'status':'PASS' if len(runs)==2 and all(x['status']=='PASS' and x['cleanupSuccess'] for x in runs) else 'FAIL','scope':'STATIC_COMPONENTS_ONLY_NOT_AV_APP_OR_MODEL_ACCURACY','sourceSHA256':SOURCE,'imageId':image,'suites':[{'suite':x['suite'],'status':x['status'],'passed':x.get('result',{}).get('passed'),'cleanupSuccess':x['cleanupSuccess']} for x in runs]}
    (out/'summary.json').write_text(json.dumps(result,sort_keys=True,indent=2)+'\n',encoding='utf-8');print(json.dumps(result,sort_keys=True));return 0 if result['status']=='PASS' else 2
if __name__=='__main__':
    try:raise SystemExit(main())
    except SystemExit:raise
    except Exception as e:print(json.dumps({'status':'REFUSED','failureType':type(e).__name__,'scope':'NO_ACCEPTANCE_CLAIM'}));raise SystemExit(2)
