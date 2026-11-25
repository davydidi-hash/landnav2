const J=(o,s=200)=>new Response(JSON.stringify(o),{status:s,headers:{'content-type':'application/json','cache-control':'no-store'}});
const STATUS=['Submitted','Referred','In mediation','Resolved','Escalated to court'];
const LEVELS=['Local mediation','District Land Office','Magistrates Court','High Court','Court of Appeal'];
const clip=(s,n)=>String(s??'').slice(0,n);
const hex=b=>[...new Uint8Array(b)].map(x=>x.toString(16).padStart(2,'0')).join('');
const audit=(env,who,action,ref)=>env.DB.prepare('INSERT INTO audit(t,who,action,ref) VALUES(?,?,?,?)').bind(new Date().toISOString(),who,action,ref||'').run();

async function hashPw(pw,salt){
 const k=await crypto.subtle.importKey('raw',new TextEncoder().encode(pw),'PBKDF2',false,['deriveBits']);
 return hex(await crypto.subtle.deriveBits({name:'PBKDF2',hash:'SHA-256',salt:new TextEncoder().encode(salt),iterations:100000},k,256));
}
async function who(req,env){
 const t=(req.headers.get('authorization')||'').replace('Bearer ','');
 if(!t)return null;
 return env.DB.prepare('SELECT o.username,o.name,o.role FROM sessions s JOIN officers o ON o.username=s.username WHERE s.token=? AND s.expires>? AND o.active=1').bind(t,Date.now()).first();
}
async function addOfficer(env,b,role){
 const un=clip(b.username,40).toLowerCase(),pw=String(b.password||''),nm=clip(b.name,80).trim();
 if(!/^[a-z0-9._-]{3,40}$/.test(un)||pw.length<10||!nm)return J({error:'invalid'},400);
 if(await env.DB.prepare('SELECT 1 x FROM officers WHERE lower(name)=lower(?)').bind(nm).first())return J({error:'exists'},409);
 const salt=hex(crypto.getRandomValues(new Uint8Array(16)));
 try{await env.DB.prepare('INSERT INTO officers(username,name,role,salt,hash) VALUES(?,?,?,?,?)').bind(un,nm,role,salt,await hashPw(pw,salt)).run()}
 catch(e){return J({error:'exists'},409)}
 return J({ok:true},201);
}
function msisdn(p){const d=String(p||'').replace(/[^\d+]/g,'');if(/^\+256\d{9}$/.test(d))return d;if(/^256\d{9}$/.test(d))return'+'+d;if(/^0\d{9}$/.test(d))return'+256'+d.slice(1);return null}
async function sms(env,phone,msg){
 const to=msisdn(phone);
 if(!to||!env.AT_API_KEY||!env.AT_USERNAME)return false;
 const host=env.AT_SANDBOX==='1'?'api.sandbox.africastalking.com':'api.africastalking.com';
 const f=new URLSearchParams({username:env.AT_USERNAME,to,message:msg});if(env.AT_SENDER)f.set('from',env.AT_SENDER);
 try{const r=await fetch(`https://${host}/version1/messaging`,{method:'POST',headers:{apiKey:env.AT_API_KEY,accept:'application/json','content-type':'application/x-www-form-urlencoded'},body:f});return r.ok}catch(e){return false}
}
function clean(b){
 if(!b||!/^LND-2026-[A-Z0-9]{5}$/.test(b.ref)||b.consent!==true)return null;
 const arr=x=>Array.isArray(x)?x:[];
 const photos=arr(b.photos).filter(p=>typeof p==='string'&&p.startsWith('data:image/jpeg;base64,')&&p.length<400000).slice(0,4);
 const g=b.gps&&Number.isFinite(b.gps.lat)&&Number.isFinite(b.gps.lng)?{lat:b.gps.lat,lng:b.gps.lng}:null;
 return{ref:b.ref,name:clip(b.name,80),phone:clip(b.phone,20),district:clip(b.district,40),village:clip(b.village,80),
  type:clip(b.type,60),tenure:clip(b.tenure,30),desc:clip(b.desc,2000),threat:!!b.threat,mediated:!!b.mediated,
  docs:arr(b.docs).slice(0,10).map(d=>clip(d,60)),photos,gps:g,consent:true,
  log:[{t:new Date().toISOString(),s:'Submitted',n:'Report received by the system'}]};
}
// Citizens tracking by case number see progress only: no name, phone, description, photos or coordinates.
const publicView=(d,status)=>({ref:d.ref,status,type:d.type,tenure:d.tenure,village:d.village,district:d.district,
 threat:d.threat,mediated:d.mediated,docs:d.docs,photos:d.photos.map(()=>''),gps:d.gps?{}:null,log:d.log});

// Overlap check: two cases pinned within CLASH_M metres may share or border the same plot. A flag for officers to verify, not proof.
const CLASH_M=75;
const dist=(a,b)=>{const r=x=>x*Math.PI/180,R=6371000,dl=r(b.lat-a.lat),dg=r(b.lng-a.lng),h=Math.sin(dl/2)**2+Math.cos(r(a.lat))*Math.cos(r(b.lat))*Math.sin(dg/2)**2;return 2*R*Math.asin(Math.sqrt(h))};
const PINS="SELECT ref,status,type,district,threat,json_extract(data,'$.gps.lat') lat,json_extract(data,'$.gps.lng') lng FROM cases WHERE json_extract(data,'$.gps.lat') IS NOT NULL LIMIT 2000";

const handle=async(req,env,ctx)=>{
 const u=new URL(req.url),p=u.pathname,M=req.method;
 if(!p.startsWith('/api/'))return new Response('Not found',{status:404});
 try{
  if(p==='/api/setup'&&M==='POST'){
   const b=await req.json().catch(()=>({}));
   const n=await env.DB.prepare('SELECT COUNT(*) c FROM officers').first();
   if(n.c>0||!env.SETUP_KEY||b.key!==env.SETUP_KEY)return J({error:'forbidden'},403);
   return addOfficer(env,b,'admin');
  }
  if(p==='/api/login'&&M==='POST'){
   const b=await req.json().catch(()=>({})),un=clip(b.username,80).trim().toLowerCase();
   const f=await env.DB.prepare("SELECT COUNT(*) c FROM audit WHERE who=? AND action='login_fail' AND t>?").bind(un,new Date(Date.now()-900000).toISOString()).first();
   if(f.c>=5)return J({error:'locked'},429);
   let o=await env.DB.prepare('SELECT * FROM officers WHERE username=? AND active=1').bind(un).first();
   if(!o){const r=await env.DB.prepare('SELECT * FROM officers WHERE lower(name)=? AND active=1').bind(un).all();if(r.results.length===1)o=r.results[0]}
   if(!o||await hashPw(String(b.password||''),o.salt)!==o.hash){await audit(env,un,'login_fail');return J({error:'bad'},401)}
   await env.DB.prepare('DELETE FROM sessions WHERE expires<?').bind(Date.now()).run();
   const token=hex(crypto.getRandomValues(new Uint8Array(32)));
   await env.DB.prepare('INSERT INTO sessions(token,username,expires) VALUES(?,?,?)').bind(token,un,Date.now()+43200000).run();
   await audit(env,un,'login');
   return J({token,name:o.name,role:o.role});
  }
  if(p==='/api/officers'&&M==='POST'){
   const me=await who(req,env);
   if(!me||me.role!=='admin')return J({error:'unauthorised'},401);
   const b=await req.json().catch(()=>({}));
   await audit(env,me.username,'add_officer',clip(b.username,40));
   return addOfficer(env,b,b.role==='admin'?'admin':'officer');
  }
  if(p==='/api/cases'&&M==='POST'){
   const d=clean(await req.json().catch(()=>null));
   if(!d)return J({error:'invalid'},400);
   const body=JSON.stringify(d);
   if(body.length>1500000)return J({error:'too large'},413);
   const r=await env.DB.prepare('INSERT OR IGNORE INTO cases(ref,status,type,district,threat,created,data) VALUES(?,?,?,?,?,?,?)')
    .bind(d.ref,'Submitted',d.type,d.district,d.threat?1:0,d.log[0].t,body).run();
   if(r.meta.changes)ctx.waitUntil(sms(env,d.phone,`Case ${d.ref} received. Track it with this number at ${env.APP_URL||u.origin}`));
   return J({ok:true,ref:d.ref},201);
  }
  if(p==='/api/map'&&M==='GET'){
   const me=await who(req,env);
   if(!me)return J({error:'unauthorised'},401);
   await audit(env,me.username,'map');
   const r=(await env.DB.prepare(PINS).all()).results.map(x=>({...x,threat:!!x.threat}));
   r.forEach(a=>{a.near=r.filter(b=>b.ref!==a.ref&&dist(a,b)<=CLASH_M).map(b=>({ref:b.ref,m:Math.round(dist(a,b))}))});
   return J(r);
  }
  if(p==='/api/cases'&&M==='GET'){
   const me=await who(req,env);
   if(!me)return J({error:'unauthorised'},401);
   await audit(env,me.username,'list');
   const r=await env.DB.prepare('SELECT ref,status,type,district,threat,created FROM cases ORDER BY created DESC LIMIT 200').all();
   return J(r.results);
  }
  const m=p.match(/^\/api\/cases\/([A-Z0-9-]{1,20})$/);
  if(m){
   const ref=m[1];
   const row=await env.DB.prepare('SELECT status,data FROM cases WHERE ref=?').bind(ref).first();
   if(!row)return J({error:'not found'},404);
   const d=JSON.parse(row.data);
   if(M==='GET'){
    if(u.searchParams.get('full')){
     const me=await who(req,env);
     if(!me)return J({error:'unauthorised'},401);
     await audit(env,me.username,'view',ref);
     const h=await env.DB.prepare('SELECT id,t,by_name,level,status,notes,resolution,challenges,photos FROM history WHERE ref=? ORDER BY id').bind(ref).all();
     const a=await env.DB.prepare('SELECT hist_id,name,verified FROM attendance WHERE ref=? ORDER BY id').bind(ref).all();
     const all=d.gps&&d.gps.lat!=null?(await env.DB.prepare(PINS).all()).results:[];
     const nearby=all.filter(b=>b.ref!==ref&&dist(d.gps,b)<=CLASH_M).map(b=>({ref:b.ref,type:b.type,status:b.status,m:Math.round(dist(d.gps,b))}));
     return J({...d,status:row.status,nearby,history:h.results.map(({id,...x})=>({...x,photos:JSON.parse(x.photos||'[]'),attendees:a.results.filter(y=>y.hist_id===id).map(y=>({name:y.name,verified:!!y.verified}))}))});
    }
    return J(publicView(d,row.status));
   }
   if(M==='PATCH'){
    const me=await who(req,env);
    if(!me)return J({error:'unauthorised'},401);
    const b=await req.json().catch(()=>({}));
    if(!STATUS.includes(b.status))return J({error:'bad status'},400);
    const t=new Date().toISOString(),lvl=LEVELS.includes(b.level)?b.level:'';
    const ph=(Array.isArray(b.photos)?b.photos:[]).filter(p=>typeof p==='string'&&p.startsWith('data:image/jpeg;base64,')&&p.length<300000).slice(0,3);
    const at=(Array.isArray(b.attendees)?b.attendees:[]).slice(0,8).map(a=>({name:clip(a&&a.name,80).trim(),verified:a&&a.verified===true?1:0})).filter(a=>a.name); // names + scan result only: ID photos/numbers are never stored
    d.log.push({t,s:b.status,n:clip(b.note,200)||'Status updated'}); // public progress line (citizens see this)
    await env.DB.batch([
     env.DB.prepare('UPDATE cases SET status=?,data=? WHERE ref=?').bind(b.status,JSON.stringify(d),ref),
     env.DB.prepare('INSERT INTO history(ref,t,by_user,by_name,level,status,notes,resolution,challenges,photos) VALUES(?,?,?,?,?,?,?,?,?,?)')
      .bind(ref,t,me.username,me.name,lvl,b.status,clip(b.notes,4000),clip(b.resolution,2000),clip(b.challenges,2000),JSON.stringify(ph)),
     ...at.map(a=>env.DB.prepare('INSERT INTO attendance(hist_id,ref,name,verified) VALUES((SELECT id FROM history WHERE ref=? AND t=?),?,?,?)').bind(ref,t,ref,a.name,a.verified))]); // officers-only record (attendance proof)
    await audit(env,me.username,'update:'+b.status,ref);
    return J({ok:true,sms:await sms(env,d.phone,`Case ${ref} is now: ${b.status}.`)});
   }
  }
  return J({error:'not found'},404);
 }catch(e){return J({error:'server error'},500)}
};

// CORS: the app lives on GitHub Pages, the API lives here. Only origins in ALLOWED_ORIGIN (comma-separated) may call it.
export default{async fetch(req,env,ctx){
 const o=req.headers.get('origin'),ok=o&&String(env.ALLOWED_ORIGIN||'').split(',').map(x=>x.trim()).includes(o);
 const cors={'access-control-allow-origin':ok?o:'null','access-control-allow-methods':'GET,POST,PATCH,OPTIONS','access-control-allow-headers':'authorization,content-type','access-control-max-age':'86400',vary:'Origin'};
 if(req.method==='OPTIONS')return new Response(null,{status:204,headers:cors});
 const r=await handle(req,env,ctx),h=new Headers(r.headers);
 for(const k in cors)h.set(k,cors[k]);
 return new Response(r.body,{status:r.status,headers:h});
}};
