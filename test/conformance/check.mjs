// Run from the standalone SDK root after building. No live API calls.
import assert from 'node:assert/strict';
import {spawn} from 'node:child_process';
import {createServer} from 'node:http';
import {readFile} from 'node:fs/promises';
import {createHash} from 'node:crypto';
import {writeFile} from 'node:fs/promises';
const command=process.env.SDK_TEST_COMMAND ? JSON.parse(process.env.SDK_TEST_COMMAND) : ["target/debug/conformance"];
assert(Array.isArray(command) && command.length && command.every(item=>typeof item==='string'),'Invalid instrumentation runner');
const contract=JSON.parse(await readFile('contract.json','utf8'));
const verifier='dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk';
const challenge='E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM';
const token='aop_'+'a'.repeat(43);
const profile={subject:'google:123',provider:'google',providerSubject:'123',name:null,username:null,email:null,emailVerified:false,avatarUrl:null};
const tokenResponse={access_token:token,token_type:'Bearer',expires_in:900,scope:'profile'};
const providers=[{id:'google',configured:true,enabled:true,available:true},{id:'github',configured:false,enabled:false,available:false}];
let scenario={status:200,body:tokenResponse},requests=[],count=0;
const exercised=new Set();
const server=createServer(async(req,res)=>{let raw='';for await(const chunk of req)raw+=chunk;requests.push({method:req.method,path:req.url,headers:req.headers,raw});const s=scenario;if(s.delay)await new Promise(resolve=>setTimeout(resolve,s.delay));res.writeHead(s.status,{'Content-Type':s.raw?'text/plain':'application/json',...(s.redirect?{Location:s.redirect}:{})});if(s.bodyDelay){res.flushHeaders();await new Promise(resolve=>setTimeout(resolve,s.bodyDelay));}res.end(s.status===204?'':s.raw??JSON.stringify(s.body));});
await new Promise(resolve=>server.listen(0,'127.0.0.1',resolve));
const baseUrl='http://127.0.0.1:'+server.address().port;
function run(action,params={},config={}){return new Promise((resolve,reject)=>{const child=spawn(command[0],command.slice(1),{stdio:['pipe','pipe','pipe']});let stdout='',stderr='';child.stdout.on('data',c=>stdout+=c);child.stderr.on('data',c=>stderr+=c);child.on('error',reject);child.on('close',code=>{try{assert.equal(code,0,'runner exit');assert.equal(stderr,'','runner stderr');resolve(JSON.parse(stdout));}catch(e){reject(e);}});child.stdin.end(JSON.stringify({action,baseUrl,clientId:'client +/&',clientSecret:'test-secret',params,...config}));});}
async function success(action,p,expected,config){const out=await run(action,p,config);assert.equal(out.ok,true,action);if(expected!==undefined)assert.deepEqual(out.result,expected,action);exercised.add(action);count++;return out.result;}
async function failure(action,p,status=0,code='invalid_argument',config){const out=await run(action,p,config);assert.equal(out.ok,false,action);assert.equal(out.error.status,status,action);assert.equal(out.error.code,code,action);assert.equal(typeof out.error.message,'string');count++;return out;}
const exchange={code:'test-code',codeVerifier:verifier,redirectUri:'https://app.example/callback'};
const callback={callbackUrl:'https://app.example/callback?code=test-code&state=abcdefghijklmnop',redirectUri:'https://app.example/callback',state:'abcdefghijklmnop',expiresAt:Math.floor(Date.now()/1000)+600};
try{
 await success('pkceChallenge',{codeVerifier:verifier},challenge);
 for(const v of ['', 'a'.repeat(42),'a'.repeat(129),verifier+'\n', 'é'.repeat(43)])await failure('pkceChallenge',{codeVerifier:v});
 const t=await success('createTransaction');assert.match(t.state,/^[A-Za-z0-9_-]{43}$/);assert.match(t.codeVerifier,/^[A-Za-z0-9_-]{43}$/);assert.notEqual(t.state,t.codeVerifier);assert.equal(t.expiresAt-t.createdAt,600);assert.equal(t.codeChallenge,createHash('sha256').update(t.codeVerifier).digest('base64url'));assert.equal(Number.isInteger(t.createdAt),true);
 const next=await success('createTransaction');assert.notEqual(t.state,next.state);assert.notEqual(t.codeVerifier,next.codeVerifier);
 const auth={provider:'google',redirectUri:exchange.redirectUri,state:'state +/%?abcdefghijklmnop',codeChallenge:challenge};
 const url=await success('authorizationUrl',auth);const u=new URL(url);assert.equal(u.pathname,'/authorize');assert.equal(u.searchParams.get('client_id'),'client +/&');for(const[k,v]of Object.entries({provider:auth.provider,redirect_uri:auth.redirectUri,state:auth.state,code_challenge:challenge,response_type:'code',code_challenge_method:'S256'}))assert.equal(u.searchParams.get(k),v);assert.equal(u.searchParams.has('client_secret'),false);
 for(const p of [{provider:'other'},{state:'short'},{codeChallenge:'bad'},{redirectUri:'https://app.example/callback?x=1'},{redirectUri:'http://example.com/callback'},{redirectUri:'https://user:pass@app.example/callback'},{redirectUri:'https://app.example/callback#'}])await failure('authorizationUrl',{...auth,...p});
 await success('authorizationUrl',{...auth,provider:'github',redirectUri:'http://[::1]:1234/callback'});
 await failure('authorizationUrl',{...auth,redirectUri:'https://app.example/'+ 'a'.repeat(2048)});
 await success('validateCallback',callback,{code:'test-code',state:callback.state});
 await success('validateCallback',{...callback,callbackUrl:'https://app.example/callback?error=access_denied&state='+callback.state},{error:'access_denied',state:callback.state});
 await failure('validateCallback',{...callback,callbackUrl:callback.callbackUrl+'&%73tate='+callback.state});
 await failure('validateCallback',{...callback,callbackUrl:callback.callbackUrl+'&other=%ZZ'});
 for(const query of ['code=x&state=wrong','code=x&state='+callback.state+'&state='+callback.state,'code=x&code=y&state='+callback.state,'error=x&error=y&state='+callback.state,'code=x&error=y&state='+callback.state,'code=&state='+callback.state,'state='+callback.state,'error=&state='+callback.state])await failure('validateCallback',{...callback,callbackUrl:callback.redirectUri+'?'+query});
 for(const p of [{expiresAt:0},{expiresAt:Math.floor(Date.now()/1000)},{expiresAt:callback.expiresAt+0.5},{expiresAt:String(callback.expiresAt)},{callbackUrl:callback.callbackUrl+'#fragment'},{callbackUrl:callback.callbackUrl.replace('/callback?','/callback/?')},{callbackUrl:callback.callbackUrl.replace('app.example','other.example')}])await failure('validateCallback',{...callback,...p});
  for(const base of ['http://example.com','https://user:pass@example.com','https://@example.com','https://example.com/path','https://example.com/path/..','https://example.com?x=1','https://example.com?','https://example.com#fragment','https://example.com#'])await failure('createTransaction',{},0,'invalid_argument',{baseUrl:base});
 for(const [action,params,body]of [['exchangeCode',exchange,tokenResponse],['profile',{accessToken:token},profile],['providers',{},providers],['revoke',{accessToken:token},null]]){
  const op=contract.operations[action];requests=[];scenario={status:op.successStatus,body};await success(action,params,body);assert.equal(requests.length,1);const req=requests[0];assert.equal(req.method,op.method);assert.equal(req.path,op.path);
   assert.match(req.headers['user-agent'],/^AnyOAuth-[a-z]+\/[0-9.]+$/,'Honest SDK product identifier');
   if(op.auth==='client'){assert.equal(req.headers.authorization,undefined);assert.match(req.headers['content-type'],/^application\/json/);assert.deepEqual(JSON.parse(req.raw),{grant_type:'authorization_code',client_id:'client +/&',client_secret:'test-secret',code:exchange.code,redirect_uri:exchange.redirectUri,code_verifier:verifier});}else{assert.equal(req.raw,'');assert.equal(req.headers.authorization,op.auth==='bearer'?'Bearer '+token:undefined);}
 }
 // Exercise every schema-required property, including nullable properties being absent.
 for(const[action,params,valid]of [['exchangeCode',exchange,tokenResponse],['profile',{accessToken:token},profile],['providers',{},providers]]){
  const op=contract.operations[action];let s=contract.schemas[op.responseSchema];if(s.type==='array')s=contract.schemas[s.items.$ref.split('/').at(-1)];
  for(const key of s.required){const obj=structuredClone(Array.isArray(valid)?valid[0]:valid);delete obj[key];scenario={status:200,body:Array.isArray(valid)?[obj]:obj};await failure(action,params,200,'protocol_error');}
  for(const key of s.required){let desc=s.properties[key];if(desc.$ref)desc=contract.schemas[desc.$ref.split('/').at(-1)];if([].concat(desc.type).includes('null'))continue;const obj=structuredClone(Array.isArray(valid)?valid[0]:valid);obj[key]=null;scenario={status:200,body:Array.isArray(valid)?[obj]:obj};await failure(action,params,200,'protocol_error');}
  scenario={status:200,body:{wrong:true}};await failure(action,params,200,'protocol_error');
  scenario={status:200,raw:'not JSON'};await failure(action,params,200,'protocol_error');
  scenario={status:200,raw:JSON.stringify(valid)+' {}'};await failure(action,params,200,'protocol_error');
  scenario={status:200,raw:JSON.stringify(valid).replaceAll('"',"'")};await failure(action,params,200,'protocol_error');
 }
 for(const bad of [{provider:'other'},{emailVerified:null},{name:42},{emailVerified:'false'},{subject:null}]){scenario={status:200,body:{...profile,...bad}};await failure('profile',{accessToken:token},200,'protocol_error');}
 for(const bad of [{expires_in:'900'},{expires_in:901},{token_type:'bearer'},{scope:'other'},{access_token:'bad'}]){scenario={status:200,body:{...tokenResponse,...bad}};await failure('exchangeCode',exchange,200,'protocol_error');}
 scenario={status:200,raw:JSON.stringify(tokenResponse).replace('"expires_in":900','"expires_in":900.0')};await success('exchangeCode',exchange,tokenResponse);
 scenario={status:200,body:{...profile,additive:{hello:true}}};await success('profile',{accessToken:token},scenario.body);
 scenario={status:400,body:{error:'invalid_grant',message:'Code expired'}};const err=await failure('exchangeCode',exchange,400,'invalid_grant');assert.equal(err.error.message,'Code expired');
 scenario={status:401,body:{error:'unauthorized'}};await failure('profile',{accessToken:token},401,'unauthorized');
 for(const bad of [{message:'Missing error'},{error:42},{error:'invalid_grant',message:null}]){scenario={status:400,body:bad};await failure('exchangeCode',exchange,400,'protocol_error');}
 scenario={status:503,raw:'unavailable'};requests=[];await failure('exchangeCode',exchange,503,'protocol_error');assert.equal(requests.length,1);
 scenario={status:429,body:{error:'rate_limited'}};requests=[];await failure('exchangeCode',exchange,429,'rate_limited');assert.equal(requests.length,1);
 for(const status of [301,302,303,307,308]){scenario={status,redirect:baseUrl+'/must-not-follow',raw:'redirect'};requests=[];await failure('exchangeCode',exchange,status,'protocol_error');assert.equal(requests.length,1);assert.equal(requests[0].path,contract.operations.exchangeCode.path);}
 scenario={status:201,body:tokenResponse};await failure('exchangeCode',exchange,201,'protocol_error');
 for(const p of [{code:''},{code:null},{codeVerifier:'bad'},{redirectUri:'http://example.com/callback'}]){requests=[];await failure('exchangeCode',{...exchange,...p});assert.equal(requests.length,0);}
 requests=[];await failure('exchangeCode',exchange,0,'invalid_argument',{clientSecret:''});assert.equal(requests.length,0);
 requests=[];await failure('profile',{accessToken:''});assert.equal(requests.length,0);
 scenario={status:200,body:tokenResponse,delay:11500};requests=[];const start=Date.now();await failure('exchangeCode',exchange,0,'transport_error');assert.ok(Date.now()-start>=9000&&Date.now()-start<11500+(command[0]==='go'?2000:0),'10s timeout');assert.equal(requests.length,1);
 scenario={status:200,body:tokenResponse,bodyDelay:11500};requests=[];const bodyStart=Date.now();const bodyTimeout=await run('exchangeCode',exchange);assert.equal(bodyTimeout.ok,false);assert.ok(['transport_error','protocol_error'].includes(bodyTimeout.error.code));assert.ok(Date.now()-bodyStart>=9000&&Date.now()-bodyStart<11500+(command[0]==='go'?2000:0),'10s body timeout');assert.equal(requests.length,1);count++;
  console.log('PASS '+count+' conformance cases (helpers, wire, schemas, errors, redirects, no retries, 10s timeout)');
  const expected=[...Object.keys(contract.operations),'pkceChallenge','createTransaction','authorizationUrl','validateCallback'].sort();
  assert.deepEqual([...exercised].sort(),expected,'100% public operation/helper execution');
  if(process.env.SDK_COVERAGE_REPORT)await writeFile(process.env.SDK_COVERAGE_REPORT,JSON.stringify({kind:'method-execution',expected,exercised:[...exercised].sort(),percent:100,cases:count})+'\n');
}finally{server.closeAllConnections();await new Promise(resolve=>server.close(resolve));}
