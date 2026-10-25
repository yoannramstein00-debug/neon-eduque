const json=(obj,status=200)=>new Response(JSON.stringify(obj),{status,headers:{'Content-Type':'application/json; charset=utf-8','Cache-Control':'no-store'}});
const enc=new TextEncoder();
const safe=(v,max=500)=>String(v??'').trim().slice(0,max);
const services={bilan:60,individuelle:60,chiot:60,forfait:60,visite:30,promenade30:30,promenade60:60,presence:120,garde3:180,garde4:240,garde6:360,garde8:480,garde12:720,garde24:1440,garde7j:10080};
const validDate=s=>/^\d{4}-\d{2}-\d{2}$/.test(s)&&!Number.isNaN(Date.parse(s+'T12:00:00Z'));
async function signature(secret,value){const key=await crypto.subtle.importKey('raw',enc.encode(secret),{name:'HMAC',hash:'SHA-256'},false,['sign']);const bytes=new Uint8Array(await crypto.subtle.sign('HMAC',key,enc.encode(value)));return [...bytes].map(x=>x.toString(16).padStart(2,'0')).join('');}
function eq(a,b){if(a.length!==b.length)return false;let n=0;for(let i=0;i<a.length;i++)n|=a.charCodeAt(i)^b.charCodeAt(i);return n===0;}
async function auth(req,env){if(!env.ADMIN_PASSWORD||!env.SESSION_SECRET)return false;const m=(req.headers.get('Cookie')||'').match(/(?:^|;\s*)neon_admin=([^;]+)/);if(!m)return false;const [exp,sig]=decodeURIComponent(m[1]).split('.');if(!/^\d+$/.test(exp)||Number(exp)<Date.now()||!sig)return false;return eq(sig,await signature(env.SESSION_SECRET,exp));}
async function main({request,env,params}){
 if(!env.DB)return json({error:'Base de données non configurée'},503);
 const path=Array.isArray(params.path)?params.path.join('/'):params.path||'';const method=request.method;
 if(!['GET','HEAD','OPTIONS'].includes(method)){const origin=request.headers.get('Origin');if(origin&&origin!==new URL(request.url).origin)return json({error:'Origine non autorisée'},403);}
 try{
 if(path==='login'&&method==='POST'){
  const ip=request.headers.get('CF-Connecting-IP')||'unknown';const ipHash=await signature(env.SESSION_SECRET||'missing',ip);const attempt=await env.DB.prepare('SELECT failures,locked_until FROM login_attempts WHERE ip_hash=?').bind(ipHash).first();if(attempt&&attempt.locked_until>Date.now())return json({error:'Trop de tentatives, réessayez plus tard'},429);
  if(!env.ADMIN_PASSWORD||!env.SESSION_SECRET)return json({error:'Accès administrateur non configuré'},503);
  const body=await request.json();if(!eq(safe(body.password,300),env.ADMIN_PASSWORD)){const failures=(attempt?.failures||0)+1;await env.DB.prepare('INSERT INTO login_attempts(ip_hash,failures,locked_until) VALUES(?,?,?) ON CONFLICT(ip_hash) DO UPDATE SET failures=excluded.failures,locked_until=excluded.locked_until').bind(ipHash,failures,failures>=5?Date.now()+15*60000:0).run();return json({error:'Identifiants incorrects'},401)}
  await env.DB.prepare('DELETE FROM login_attempts WHERE ip_hash=?').bind(ipHash).run();
  const exp=String(Date.now()+8*3600000);const sig=await signature(env.SESSION_SECRET,exp);
  return new Response(JSON.stringify({ok:true}),{headers:{'Content-Type':'application/json','Set-Cookie':`neon_admin=${exp}.${sig}; Path=/api; HttpOnly; Secure; SameSite=Strict; Max-Age=28800`,'Cache-Control':'no-store'}});
 }
 if(path==='logout'&&method==='POST')return new Response(JSON.stringify({ok:true}),{headers:{'Content-Type':'application/json','Set-Cookie':'neon_admin=; Path=/api; HttpOnly; Secure; SameSite=Strict; Max-Age=0'}});
 if(path==='availability'&&method==='GET'){
  const u=new URL(request.url),date=safe(u.searchParams.get('date'),10),service=safe(u.searchParams.get('service'),30);
  if(!validDate(date)||!services[service])return json({error:'Date ou prestation invalide'},400);
  const busy=(await env.DB.prepare("SELECT booking_date,booking_time,duration_minutes FROM bookings WHERE status='confirmed' AND booking_date BETWEEN ? AND ?").bind(new Date(Date.parse(date+'T12:00:00Z')-7*86400000).toISOString().slice(0,10),date).all()).results;
  const blocks=(await env.DB.prepare('SELECT starts_at,ends_at FROM blocked_times WHERE ends_at>? AND starts_at<?').bind(date+'T00:00',date+'T23:59').all()).results;
  const slots=[];const duration=services[service];const day=new Date(date+'T12:00:00Z').getUTCDay();
  const windows=day===0?[]:day===6?[[9,12],[14,17]]:[[9,12],[14,18]];
  for(const [start,end] of windows)for(let m=start*60;m+duration<=end*60;m+=60){const hh=String(Math.floor(m/60)).padStart(2,'0')+':'+String(m%60).padStart(2,'0');const begin=Date.parse(date+'T'+hh+':00Z'),finish=begin+duration*60000;
   if(busy.some(b=>{const st=Date.parse(b.booking_date+'T'+b.booking_time+':00Z');return begin<st+b.duration_minutes*60000&&finish>st})||blocks.some(b=>begin<Date.parse(b.ends_at+':00Z')&&finish>Date.parse(b.starts_at+':00Z')))continue;
   slots.push(hh);
  }
  return json({date,service,slots,notice:'Créneaux indicatifs : la confirmation reste manuelle.'});
 }
 if(path==='bookings'&&method==='POST'){
  const b=await request.json();const serviceKey=safe(b.service_key,30);const name=safe(b.name,120),phone=safe(b.phone,50),city=safe(b.city,120),service=safe(b.service,180),date=safe(b.date,10),time=safe(b.time,5),notes=safe(b.notes,2000);
  if(!name||!phone||!city||!service||!services[serviceKey]||!validDate(date)||!/^([01]\d|2[0-3]):[0-5]\d$/.test(time))return json({error:'Champs manquants ou invalides'},400);
  if(date<new Date().toISOString().slice(0,10))return json({error:'Date passée'},400);
  const reference='NE-'+crypto.randomUUID().slice(0,8).toUpperCase();
  const client=await env.DB.prepare('INSERT INTO clients(name,phone,city) VALUES(?,?,?) RETURNING id').bind(name,phone,city).first();
  await env.DB.prepare('INSERT INTO bookings(reference,client_id,service,service_key,duration_minutes,booking_date,booking_time,notes) VALUES(?,?,?,?,?,?,?,?)').bind(reference,client.id,service,serviceKey,services[serviceKey],date,time,notes).run();
  return json({ok:true,reference,status:'pending'},201);
 }
 if(!await auth(request,env))return json({error:'Authentification requise'},401);
 if(path==='me'&&method==='GET')return json({ok:true});
 if(path==='dashboard'&&method==='GET'){const counts=(await env.DB.prepare('SELECT status,COUNT(*) count FROM bookings GROUP BY status').all()).results;const clients=await env.DB.prepare('SELECT COUNT(*) count FROM clients').first();return json({counts,clients:clients.count})}
 if(path==='blocked-times'&&method==='GET')return json({items:(await env.DB.prepare('SELECT * FROM blocked_times ORDER BY starts_at DESC LIMIT 300').all()).results});
 if(path==='blocked-times'&&method==='POST'){const b=await request.json(),start=safe(b.starts_at,16),end=safe(b.ends_at,16);if(!/^\d{4}-\d\d-\d\dT\d\d:\d\d$/.test(start)||!/^\d{4}-\d\d-\d\dT\d\d:\d\d$/.test(end)||end<=start)return json({error:'Période invalide'},400);await env.DB.prepare('INSERT INTO blocked_times(starts_at,ends_at,reason) VALUES(?,?,?)').bind(start,end,safe(b.reason,300)).run();return json({ok:true},201)}
 const blockMatch=path.match(/^blocked-times\/(\d+)$/);if(blockMatch&&method==='DELETE'){await env.DB.prepare('DELETE FROM blocked_times WHERE id=?').bind(Number(blockMatch[1])).run();return json({ok:true})}
 if(path==='bookings'&&method==='GET')return json({items:(await env.DB.prepare('SELECT b.*,c.name client_name,c.phone client_phone,c.email client_email FROM bookings b JOIN clients c ON c.id=b.client_id ORDER BY b.booking_date DESC,b.booking_time DESC LIMIT 500').all()).results});
 if(path==='clients'&&method==='GET')return json({items:(await env.DB.prepare('SELECT * FROM clients ORDER BY updated_at DESC LIMIT 500').all()).results});
 if(path==='clients'&&method==='POST'){
  const b=await request.json();if(!safe(b.name,120)||!safe(b.phone,50))return json({error:'Nom et téléphone obligatoires'},400);
  const fields=['name','phone','email','city','address','dog_name','dog_breed','dog_birth','dog_notes','health_notes','notes'];const vals=fields.map(f=>safe(b[f],f.includes('notes')?4000:250));
  const r=await env.DB.prepare(`INSERT INTO clients(${fields.join(',')},consent) VALUES(${fields.map(()=>'?').join(',')},?) RETURNING id`).bind(...vals,b.consent?1:0).first();return json({ok:true,id:r.id},201);
 }
 const cm=path.match(/^clients\/(\d+)$/);if(cm&&method==='PATCH'){
  const b=await request.json();const fields=['name','phone','email','city','address','dog_name','dog_breed','dog_birth','dog_notes','health_notes','notes','consent'];const present=fields.filter(f=>Object.hasOwn(b,f));if(!present.length)return json({error:'Aucun champ'},400);
  const values=present.map(f=>f==='consent'?(b[f]?1:0):safe(b[f],f.includes('notes')?4000:250));
  await env.DB.prepare(`UPDATE clients SET ${present.map(f=>f+'=?').join(',')},updated_at=CURRENT_TIMESTAMP WHERE id=?`).bind(...values,Number(cm[1])).run();return json({ok:true});
 }
 const bm=path.match(/^bookings\/(\d+)$/);if(bm&&method==='PATCH'){
  const b=await request.json();if(!['pending','confirmed','rejected','cancelled','completed'].includes(b.status))return json({error:'Statut invalide'},400);
  if(b.status==='confirmed'){
   const current=await env.DB.prepare('SELECT booking_date,booking_time,duration_minutes FROM bookings WHERE id=?').bind(Number(bm[1])).first();if(!current)return json({error:'Réservation introuvable'},404);
   const start=Date.parse(current.booking_date+'T'+current.booking_time+':00Z'),end=start+current.duration_minutes*60000;
   const existing=(await env.DB.prepare("SELECT id,booking_date,booking_time,duration_minutes FROM bookings WHERE id<>? AND status='confirmed' AND booking_date BETWEEN ? AND ?").bind(Number(bm[1]),new Date(start-7*86400000).toISOString().slice(0,10),current.booking_date).all()).results;
   if(existing.some(x=>{const a=Date.parse(x.booking_date+'T'+x.booking_time+':00Z');return start<a+x.duration_minutes*60000&&end>a}))return json({error:'Chevauchement avec une réservation confirmée'},409);
   const blocks=(await env.DB.prepare('SELECT starts_at,ends_at FROM blocked_times WHERE ends_at>? AND starts_at<?').bind(current.booking_date+'T00:00',new Date(end).toISOString().slice(0,16)).all()).results;
   if(blocks.some(x=>start<Date.parse(x.ends_at+':00Z')&&end>Date.parse(x.starts_at+':00Z')))return json({error:'Créneau bloqué dans le planning'},409);
  }
  await env.DB.prepare('UPDATE bookings SET status=?,updated_at=CURRENT_TIMESTAMP WHERE id=?').bind(b.status,Number(bm[1])).run();return json({ok:true});
 }
 return json({error:'Route introuvable'},404);
 }catch(e){return json({error:'Erreur serveur. Vérifiez la configuration et les données.'},500)}
}
export const onRequest=main;
