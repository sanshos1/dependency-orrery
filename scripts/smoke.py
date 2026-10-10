import json,re,time
from pathlib import Path
from genlayer_py import create_account,create_client
from genlayer_py.chains import studionet
from genlayer_py.contracts import actions as contract_actions
def compat(method=None,args=None,kwargs=None):
 out={}
 if method is not None: out['method']=method
 if args: out['args']=args
 if kwargs: out['kwargs']=kwargs
 return out
contract_actions.make_calldata_object=compat
ROOT=Path(__file__).parents[1]; ENV=(ROOT.parents[3]/'accounts.env').read_text(); ADDRESS=json.loads((ROOT/'deployment.json').read_text())['contractAddress']; KEY=re.search(r'^ACCOUNT_3_GENLAYER_PRIVATE_KEY\s*=\s*"?([^"\r\n]+)',ENV,re.M).group(1).strip(); c=create_client(chain=studionet,account=create_account(account_private_key=KEY))
def write(name,args):
 tx=c.write_contract(address=ADDRESS,function_name=name,args=args); print(name+'_tx='+str(tx),flush=True); r=c.wait_for_transaction_receipt(transaction_hash=tx,wait_until='finalized',retries=180,interval=5000,full_transaction=True); leaders=r.get('consensus_data',{}).get('leader_receipt') or []; leaders=[leaders] if isinstance(leaders,dict) else leaders; assert r.get('result_name')=='MAJORITY_AGREE' and any(x.get('execution_result')=='SUCCESS' for x in leaders); return str(tx)
sid='ORBIT-'+str(int(time.time())); base='https://raw.githubusercontent.com/sanshos1/dependency-orrery/main/fixtures/'; tx={'open':write('open_scan',[sid,'Orbit renderer production reachability',base+'manifest.txt',base+'runtime-trace.txt',base+'advisory.txt'])}; opened=c.read_contract(address=ADDRESS,function_name='get_scan',args=[sid]); assert opened['state']=='OPEN'; tx['resolve']=write('resolve_scan',[sid]); final=c.read_contract(address=ADDRESS,function_name='get_scan',args=[sid]); assert final['state']=='FINALIZED' and final['finding'] in ('AFFECTED','CLEAR','INDETERMINATE'); proof={'scanId':sid,'contract':ADDRESS,'transactions':tx,'opened':opened,'final':final,'fixtureDisclosure':'Public repository fixtures demonstrate digest freezing, independent refetch, bounded reachability consensus, and terminal state.'}; (ROOT/'evidence'/'live-run.json').write_text(json.dumps(proof,indent=2)+'\n'); print(json.dumps(proof,indent=2))
