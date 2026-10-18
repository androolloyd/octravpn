"""Run the compiled unchanged-native profile oracle inside the owned fixture.
No Docker commands, network calls, package installs or source writes occur here.
"""
import argparse,datetime,hashlib,json,os,pathlib,subprocess,time
HERE=pathlib.Path(__file__).parent.resolve()
def sha(path):return hashlib.sha256(path.read_bytes()).hexdigest()
def pairs(items):
    obj={}
    for key,value in items:
        if key in obj:raise ValueError('duplicate JSON field')
        obj[key]=value
    return obj
def read(path):
    raw=path.read_bytes()
    if len(raw)>16*1024*1024:raise ValueError('fixture JSON size cap')
    return json.loads(raw.decode('utf-8'),object_pairs_hook=pairs,parse_constant=lambda _:(_ for _ in ()).throw(ValueError('nonfinite JSON')))
def main():
    parser=argparse.ArgumentParser()
    parser.add_argument('--native-bin',type=pathlib.Path,required=True)
    parser.add_argument('--native-source',type=pathlib.Path,required=True)
    parser.add_argument('--source-map',type=pathlib.Path,required=True)
    parser.add_argument('--build-provenance',type=pathlib.Path,required=True)
    parser.add_argument('--out',type=pathlib.Path,required=True)
    args=parser.parse_args()
    args.out.mkdir(exist_ok=False)
    source_map=read(args.source_map)
    assert source_map['upstream_commit']=='7f9be4489870645cfcc95439638cde40f5da9f50'
    assert len(source_map['files'])==1158
    def native_inputs():
        values={name:sha(args.native_source/name) for name in source_map['files']}
        assert values==source_map['files'],'native source body drift'
        return values
    before=native_inputs()
    source_digest=hashlib.sha256(json.dumps(before,sort_keys=True,separators=(',',':')).encode()).hexdigest()
    assert args.native_bin.is_file() and args.build_provenance.is_file()
    executable_sha=sha(args.native_bin)
    oracle_sha=sha(HERE/'profile.ml')
    inputs=read(HERE/'cases.json')
    assert inputs['schema']=='octra_native_consensus_profile_inputs_v1'
    assert len(inputs['cases'])==96 and len({item['id'] for item in inputs['cases']})==96
    base_env={key:value for key,value in os.environ.items() if not key.startswith('OCTRA_')}
    records=[];results=[]
    start=datetime.datetime.now(datetime.timezone.utc).isoformat();clock=time.monotonic()
    failed=None
    for index,case in enumerate(inputs['cases']):
        item=args.out/f'case-{index:03d}';item.mkdir()
        request=item/'input.json';request.write_text(json.dumps(case,sort_keys=True)+'\n')
        command=[str(args.native_bin.resolve()),str(request.resolve()),source_digest,oracle_sha]
        with (item/'stdout.json').open('wb') as output,(item/'stderr.log').open('wb') as error:
            try:
                result=subprocess.run(command,env={**base_env,**case['env']},stdout=output,stderr=error,timeout=60)
                code=result.returncode
            except subprocess.TimeoutExpired:code=None
        record={'id':case['id'],'command':command,'exit_code':code,'input_sha256':sha(request),'stdout':{'path':str((item/'stdout.json').resolve()),'sha256':sha(item/'stdout.json')},'stderr':{'path':str((item/'stderr.log').resolve()),'sha256':sha(item/'stderr.log')}}
        records.append(record)
        try:
            assert code==0,'native oracle process refused or timed out'
            actual=read(item/'stdout.json')
            assert actual['schema']=='octra_native_consensus_profile_case_v1'
            assert actual['id']==case['id'] and actual['env']==case['env'] and actual['chain_id']==case['chain_id']
            assert actual['valid'] is case['expect_valid']
            assert actual['native_sources_sha256']==source_digest and actual['oracle_source_sha256']==oracle_sha
            assert actual['native_pin']==source_map['upstream_commit']
            if actual['valid']:
                assert len(actual['operations'])==45
                assert [row['operation'] for row in actual['operations']]==case['operations']
                assert actual['epochs'] and actual['settings']['crypto_engine']
            else:
                assert type(actual['error']) is str and actual['settings'] is None and actual['epochs'] is None and actual['operations'] is None
            results.append(actual)
        except Exception as error:
            failed={'case':case['id'],'reason':type(error).__name__+': '+str(error)}
            break
    after=native_inputs()
    assert before==after and executable_sha==sha(args.native_bin)
    report={'schema':'octra_native_consensus_profile_capture_v1','status':'PASS_NATIVE_ONLY' if failed is None and len(results)==96 else 'FAILED','native_component_cases_passed':failed is None and len(results)==96,
      'native_pin':source_map['upstream_commit'],'native_sources_sha256':source_digest,'sources_before':before,'sources_after':after,
      'oracle_source':{'path':str((HERE/'profile.ml').resolve()),'sha256':oracle_sha},'case_inputs':{'path':str((HERE/'cases.json').resolve()),'sha256':sha(HERE/'cases.json')},
      'native_binary':{'path':str(args.native_bin.resolve()),'sha256':executable_sha},'build_provenance':{'path':str(args.build_provenance.resolve()),'sha256':sha(args.build_provenance)},
      'producer':{'path':str(pathlib.Path(__file__).resolve()),'sha256':sha(pathlib.Path(__file__))},'started_at':start,'completed_at':datetime.datetime.now(datetime.timezone.utc).isoformat(),'elapsed_seconds':time.monotonic()-clock,
      'case_count':len(results),'case_records':records,'cases':results,'failure':failed,'rust_comparator_executed':False,'whole_node_qualified':False,
      'scope':'Unchanged native validation/profile/hash/epoch-only selectors. No signature bypass, financial submission, authenticated execution-rule activation, mixed host, launch or public qualification claim.'}
    (args.out/'report.json').write_text(json.dumps(report,indent=2)+'\n')
    print(json.dumps({'status':report['status'],'cases':len(results),'report':str((args.out/'report.json').resolve()),'sha256':sha(args.out/'report.json')}))
    return 0 if report['native_component_cases_passed'] else 1
if __name__=='__main__':raise SystemExit(main())
