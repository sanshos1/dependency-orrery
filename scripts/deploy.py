import json,re,subprocess,hashlib
from pathlib import Path
from genlayer_py import create_client,create_account
from genlayer_py.chains import studionet
ROOT=Path(__file__).parents[1]; ENV=(ROOT.parents[3]/'accounts.env').read_text()
KEY=re.search(r'^ACCOUNT_3_GENLAYER_PRIVATE_KEY\s*=\s*"?([^"\r\n]+)',ENV,re.M).group(1).strip()
c=create_client(chain=studionet,account=create_account(account_private_key=KEY)); code=(ROOT/'contracts/contract.py').read_text(); tx=c.deploy_contract(code=code,args=[]); print('deploy_tx='+str(tx),flush=True)
r=c.wait_for_transaction_receipt(transaction_hash=tx,wait_until='finalized',retries=180,interval=5000,full_transaction=True); leaders=r.get('consensus_data',{}).get('leader_receipt') or []; leaders=[leaders] if isinstance(leaders,dict) else leaders
assert r.get('result_name')=='MAJORITY_AGREE' and any(x.get('execution_result')=='SUCCESS' for x in leaders)
address=r.get('data',{}).get('contract_address') or r.get('to_address'); out={'network':'StudioNet','contractAddress':address,'deploymentTransaction':str(tx),'sourceSha256':hashlib.sha256(code.encode()).hexdigest(),'sourceCommit':subprocess.check_output(['git','rev-parse','HEAD'],cwd=ROOT,text=True).strip(),'repository':'https://github.com/sanshos1/dependency-orrery','publicSite':'https://dependency-orrery.pages.dev/'}
(ROOT/'deployment.json').write_text(json.dumps(out,indent=2)+'\n'); print(json.dumps(out,indent=2))
