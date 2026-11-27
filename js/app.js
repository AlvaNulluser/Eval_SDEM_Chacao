/**
 * SDEM Chacao — Detección de Enlaces Maliciosos
 * Lógica del cliente: autenticación local, motor heurístico y vistas.
 */

const ROLES={admin:{n:'Administrador',l:4,t:['dash','scan','mail','map','users','log']},analista:{n:'Analista de seguridad',l:3,t:['dash','scan','mail','map','log']},auditor:{n:'Auditor',l:2,t:['dash','map','log']},empleado:{n:'Empleado',l:1,t:['scan','mail']}};
const TN={dash:'📊 Panel',scan:'🔍 Enlace',mail:'✉️ Correo',map:'📍 Mapa',users:'👥 Usuarios',log:'📜 Bitácora'};
const $=id=>document.getElementById(id);
let me=null,fails={},DB={users:[],hist:[],log:[],cos:[]};
const COS=[{n:'Importadora Altamira C.A.',lat:10.4959,lng:-66.8483},{n:'Logística Los Palos Grandes',lat:10.4985,lng:-66.8451},{n:'Exportaciones Chacao S.A.',lat:10.4967,lng:-66.8537},{n:'Agencia Aduanal Country Club',lat:10.4912,lng:-66.8329}];
const sv=()=>{try{localStorage.setItem('sdem',JSON.stringify(DB))}catch(e){}};
const ld=()=>{try{const d=JSON.parse(localStorage.getItem('sdem'));if(d&&d.users)DB=d}catch(e){}};
async function H(s){const b=await crypto.subtle.digest('SHA-256',new TextEncoder().encode('sdem$'+s));return[...new Uint8Array(b)].map(x=>x.toString(16).padStart(2,'0')).join('')}
async function seed(){ld();if(!DB.users.length){for(const[u,p,r]of[['admin','Admin#2026','admin'],['analista','Analista#2026','analista'],['auditor','Auditor#2026','auditor'],['empleado','Empleado#2026','empleado']])DB.users.push({u,h:await H(p),r});DB.cos=COS.slice()}
 if(!DB.demo){for(const[u,p,r]of[['jperez','Perez#2026','empleado'],['mgomez','Gomez#2026','analista']])if(!DB.users.some(x=>x.u===u))DB.users.push({u,h:await H(p),r});demo()}sv()}
function demo(){
 const U=['empleado','analista','jperez','mgomez'];
 const L=['https://www.dhl.com/ve-es/home.html','https://www.maersk.com/tracking','https://www.seniat.gob.ve/','http://seniat-verificar-cuenta.login.secure-pago.xyz/factura?id=1','http://192.168.4.20:8080/factura.exe','http://dhl-tracking-bl.top/login','https://bit.ly/3xYzAbC','https://banesco-seguridad.com-update.icu/clave','https://www.msc.com/es','http://paypal.verify-account.xn--secure-9ya.tk/login@evil.com','https://www.fedex.com/es-ve/home.html','http://mercantil-banco-online.work/confirmar-pago','https://outlook.office.com/mail','http://aduana-ve.support/awb-update?user=1','https://www.ups.com/ve/es/Home.page','http://maersk-invoice-urgente.click/descargar/factura.docm','https://www.cmacgm-group.com/es','http://factura-pendiente.zip/pago-urgente'];
 L.forEach((url,i)=>{const r=analyze(url),v=verd(r.score),t=new Date(Date.now()-(i*4+1)*3600e3*3).toLocaleString('es-VE'),u=U[i%4];DB.hist.push({t,u,url,sc:r.score,v:v[0]});DB.log.push({t,u,a:'Análisis: '+v[0]+' ('+r.score+') '+url.slice(0,60)})});
 [['admin','Inicio de sesión'],['jperez','Intento fallido'],['admin','Usuario creado: mgomez'],['analista','Inicio de sesión'],['auditor','Inicio de sesión'],['empleado','Inicio de sesión']].forEach((x,i)=>DB.log.push({t:new Date(Date.now()-(80+i*6)*3600e3).toLocaleString('es-VE'),u:x[0],a:x[1]}));
 [{n:'Aduanas y Fletes Bello Monte',lat:10.4903,lng:-66.8648},{n:'Comercial Marítima Chacao',lat:10.4989,lng:-66.8505},{n:'Distribuidora Av. Francisco de Miranda',lat:10.4994,lng:-66.8461},{n:'Transporte Internacional El Rosal',lat:10.4944,lng:-66.8559}].forEach(c=>{if(!DB.cos.some(x=>x.n===c.n))DB.cos.push(c)});
 DB.demo=1}
const now=()=>new Date().toLocaleString('es-VE');
function lg(a){DB.log.unshift({t:now(),u:me?me.u:'—',a});DB.log=DB.log.slice(0,300);sv()}
const okPw=p=>p.length>=8&&/[A-Z]/.test(p)&&/[a-z]/.test(p)&&/\d/.test(p)&&/[^\w\s]/.test(p);

async function login(){
 const u=$('u').value.trim().toLowerCase(),p=$('p').value,e=$('le');
 if(!u||!p){e.textContent='Complete usuario y contraseña.';return}
 if((fails[u]||0)>=3){e.textContent='Cuenta bloqueada temporalmente por intentos fallidos.';return}
 const x=DB.users.find(v=>v.u===u);
 if(x&&x.h===await H(p)){fails[u]=0;me=x;e.textContent='';$('p').value='';lg('Inicio de sesión');start()}
 else{fails[u]=(fails[u]||0)+1;e.textContent='Credenciales inválidas. Intentos restantes: '+Math.max(0,3-fails[u]);if(x){const t=me;me={u};lg('Intento fallido');me=t}}
}
function start(){
 $('login').classList.add('hidden');$('app').classList.remove('hidden');
 const R=ROLES[me.r];$('who').textContent='👤 '+me.u;$('rol').textContent=R.n+' · Nivel '+R.l;
 $('nav').innerHTML='';R.t.forEach(t=>{const b=document.createElement('button');b.textContent=TN[t];b.dataset.t=t;b.onclick=()=>go(t);$('nav').appendChild(b)});
 $('nr').innerHTML=Object.keys(ROLES).map(k=>`<option value="${k}">${ROLES[k].n}</option>`).join('');
 go(R.t[0]);
}
function go(t){
 if(!ROLES[me.r].t.includes(t)){lg('Acceso denegado a '+t);return}
 ['dash','scan','mail','map','users','log'].forEach(v=>$('v-'+v).classList.toggle('hidden',v!==t));
 [...$('nav').children].forEach(b=>b.classList.toggle('on',b.dataset.t===t));
 if(t==='dash')dash();if(t==='map')mapInit();if(t==='users')users();if(t==='log')logv();
}
function logout(){lg('Cierre de sesión');me=null;$('app').classList.add('hidden');$('login').classList.remove('hidden')}

/* ---------- MOTOR HEURÍSTICO ---------- */
const BRANDS=['seniat','dhl','maersk','fedex','ups','msc','cma','banesco','mercantil','provincial','paypal','microsoft','office365','aduana','sunde'];
const KW=['login','verify','verificar','secure','update','actualiza','password','clave','factura','invoice','pago','payment','tracking','bl-','awb','cuenta','suspend','bloquea','urgente','confirm'];
const TLD=['zip','xyz','top','click','tk','ml','ga','cf','gq','work','support','country','loan','rest','icu'];
const SHORT=['bit.ly','tinyurl.com','t.co','goo.gl','is.gd','ow.ly','cutt.ly','rebrand.ly','shorturl.at'];
function analyze(raw){
 let s=0;const f=[];const add=(p,m)=>{s+=p;f.push(m+' (+'+p+')')};
 let u;try{u=new URL(/^[a-z][a-z0-9+.-]*:/i.test(raw)?raw:'http://'+raw)}catch(e){return{score:100,flags:['URL con formato inválido (+100)'],host:raw}}
 const h=u.hostname.toLowerCase(),parts=h.split('.'),tld=parts[parts.length-1],base=parts.slice(-2).join('.');
 if(u.protocol!=='https:')add(15,'Protocolo no cifrado o no estándar ('+u.protocol+')');
 if(/^\d{1,3}(\.\d{1,3}){3}$/.test(h))add(30,'Usa dirección IP en lugar de dominio');
 if(raw.includes('@'))add(25,'Contiene @ (ocultamiento de destino)');
 if(h.includes('xn--'))add(25,'Dominio punycode (posible homógrafo)');
 if(parts.length>4)add(15,'Subdominios excesivos ('+parts.length+' niveles)');
 if(TLD.includes(tld))add(15,'TLD de alto riesgo .'+tld);
 if(SHORT.includes(h))add(15,'Acortador de URL que oculta destino');
 if(u.port&&!['80','443'].includes(u.port))add(10,'Puerto atípico '+u.port);
 if(raw.length>100)add(10,'URL excesivamente larga ('+raw.length+' caracteres)');
 if((raw.match(/%[0-9a-f]{2}/gi)||[]).length>4)add(10,'Codificación porcentual abusiva');
 if((h.match(/-/g)||[]).length>=3)add(10,'Demasiados guiones en el dominio');
 if((h.match(/\d/g)||[]).length>=4)add(8,'Muchos dígitos en el dominio');
 const kw=KW.filter(k=>(h+u.pathname+u.search).toLowerCase().includes(k));
 if(kw.length)add(Math.min(24,kw.length*8),'Palabras típicas de phishing: '+kw.join(', '));
 const br=BRANDS.find(b=>h.includes(b));
 if(br&&!(parts.length>=2&&parts[parts.length-2]===br))add(25,'Posible suplantación de marca: '+br);
 if(/\.(exe|scr|js|vbs|bat|cmd|msi|jar|iso|docm|xlsm)$/i.test(u.pathname))add(30,'Descarga de archivo ejecutable o con macros');
 if(!f.length)f.push('Sin indicadores de riesgo detectados');
 return{score:Math.min(100,s),flags:f,host:h}
}
const verd=s=>s>=55?['MALICIOSO','t-bad','var(--bad)']:s>=25?['SOSPECHOSO','t-wa','var(--wa)']:['SEGURO','t-ok','var(--ok)'];
function record(url,r){const v=verd(r.score);DB.hist.unshift({t:now(),u:me.u,url,sc:r.score,v:v[0]});DB.hist=DB.hist.slice(0,200);sv();lg('Análisis: '+v[0]+' ('+r.score+') '+url.slice(0,60))}
function show(el,url,r){
 const v=verd(r.score);el.innerHTML='';
 const d=document.createElement('div');d.style.marginTop='16px';
 const t=document.createElement('div');t.innerHTML=`<span class="tag ${v[1]}">${v[0]}</span> &nbsp; Puntaje de riesgo: <b>${r.score}/100</b>`;
 const m=document.createElement('div');m.className='meter';m.innerHTML=`<i style="width:${r.score}%;background:${v[2]}"></i>`;
 const p=document.createElement('div');p.textContent='🔗 '+url;p.className='note';
 const ul=document.createElement('ul');ul.className='fl';r.flags.forEach(x=>{const li=document.createElement('li');li.textContent=x;ul.appendChild(li)});
 const rec=document.createElement('div');rec.className='note';rec.textContent=r.score>=55?'Recomendación: NO abrir. Reportar al departamento de seguridad y bloquear el dominio.':r.score>=25?'Recomendación: verificar con el remitente por otro canal antes de abrir.':'Recomendación: enlace sin indicadores críticos; mantenga la precaución habitual.';
 d.append(t,m,p,ul,rec);el.appendChild(d)
}
function scan(){const x=$('url').value.trim();if(!x){$('res').textContent='Ingrese una URL.';return}const r=analyze(x);record(x,r);show($('res'),x,r)}
function mail(){
 const tx=$('mt').value;const L=[...new Set(tx.match(/(https?:\/\/|www\.)[^\s<>"')]+/gi)||[])];
 const o=$('mres');o.innerHTML='';
 const urg=['urgente','inmediato','suspendida','bloqueada','24 horas','verifique','confirme','premio','factura adjunta'].filter(k=>tx.toLowerCase().includes(k));
 const a=document.createElement('p');a.textContent=`Enlaces encontrados: ${L.length}. Lenguaje de urgencia/ingeniería social: ${urg.length?urg.join(', '):'no detectado'}.`;o.appendChild(a);
 L.forEach(l=>{const r=analyze(l);record(l,r);const d=document.createElement('div');d.className='card';show(d,l,r);o.appendChild(d)});
 if(!L.length)o.appendChild(Object.assign(document.createElement('p'),{textContent:'No se hallaron enlaces en el texto.'}))
}

/* ---------- VISTAS ---------- */
function dash(){
 const h=DB.hist,c=[0,0,0];h.forEach(x=>c[x.v==='SEGURO'?0:x.v==='SOSPECHOSO'?1:2]++);
 $('k0').firstChild.nodeValue=h.length;$('k1').firstChild.nodeValue=c[0];$('k2').firstChild.nodeValue=c[1];$('k3').firstChild.nodeValue=c[2];
 const mx=Math.max(1,...c);$('chart').innerHTML=[['Seguros','var(--ok)'],['Sospechosos','var(--wa)'],['Maliciosos','var(--bad)']].map((x,i)=>`<div class="bar" style="width:${Math.max(8,c[i]/mx*100)}%;background:${x[1]}">${x[0]}: ${c[i]}</div>`).join('');
 const t=$('tbh');t.innerHTML='<tr><th>Fecha</th><th>Usuario</th><th>Enlace</th><th>Puntaje</th><th>Veredicto</th></tr>';
 h.slice(0,10).forEach(x=>{const r=t.insertRow();[x.t,x.u,x.url,x.sc].forEach(v=>r.insertCell().textContent=v);r.insertCell().innerHTML=`<span class="tag ${x.v==='SEGURO'?'t-ok':x.v==='SOSPECHOSO'?'t-wa':'t-bad'}">${x.v}</span>`});
 if(!h.length)t.insertRow().insertCell().textContent='Aún no hay análisis registrados.'
}
function mapSet(a,b){
 const la=parseFloat(a),lo=parseFloat(b),e=$('me');
 if(isNaN(la)||isNaN(lo)||la<-90||la>90||lo<-180||lo>180){e.textContent='Coordenadas inválidas (lat −90 a 90, lng −180 a 180).';return false}
 e.textContent='';$('mf').src=`https://maps.google.com/maps?q=${la},${lo}&z=16&output=embed`;$('ml').href=`https://www.google.com/maps?q=${la},${lo}`;return true
}
function mapOpts(){$('ms').innerHTML=DB.cos.map((c,i)=>`<option value="${i}">${c.n}</option>`).join('')}
function mapInit(){mapOpts();mapSet($('la').value,$('lo').value)}
function users(){
 const t=$('tbu');t.innerHTML='<tr><th>Usuario</th><th>Rol</th><th>Nivel</th><th></th></tr>';
 DB.users.forEach(x=>{const r=t.insertRow();r.insertCell().textContent=x.u;r.insertCell().textContent=ROLES[x.r].n;r.insertCell().textContent=ROLES[x.r].l;const c=r.insertCell();if(x.u!==me.u){const b=document.createElement('button');b.className='red';b.textContent='Eliminar';b.onclick=()=>{DB.users=DB.users.filter(y=>y.u!==x.u);lg('Usuario eliminado: '+x.u);sv();users()};c.appendChild(b)}})
}
function logv(){
 const t=$('tbl');t.innerHTML='<tr><th>Fecha</th><th>Usuario</th><th>Evento</th></tr>';
 DB.log.slice(0,100).forEach(x=>{const r=t.insertRow();[x.t,x.u,x.a].forEach(v=>r.insertCell().textContent=v)})
}

/* ---------- EVENTOS ---------- */
$('loginform').addEventListener('submit',e=>{e.preventDefault();login()});
$('bo').onclick=logout;
$('th').onclick=()=>{const r=document.documentElement,d=r.dataset.theme==='dark'||(!r.dataset.theme&&matchMedia('(prefers-color-scheme:dark)').matches);r.dataset.theme=d?'light':'dark'};
$('bs').onclick=scan;$('url').onkeydown=e=>{if(e.key==='Enter')scan()};
$('bx').onclick=()=>{$('url').value='http://seniat-verificar-cuenta.login.secure-pago.xyz/factura%20update?id=1&clave=confirm'};
$('bm').onclick=mail;
$('bme').onclick=()=>{$('mt').value='Estimado cliente,\nSu cuenta aduanal será suspendida en 24 horas. Verifique su factura urgente en http://dhl-tracking-bl.top/login y descargue http://192.168.4.20:8080/factura.exe\nTambién puede consultar https://www.dhl.com/ve-es/home.html\nGracias.'};
$('mg').onclick=()=>mapSet($('la').value,$('lo').value);
$('ms').onchange=()=>{const c=DB.cos[$('ms').value];$('la').value=c.lat;$('lo').value=c.lng;mapSet(c.lat,c.lng)};
$('ma').onclick=()=>{const n=prompt('Nombre de la empresa:');if(!n||!mapSet($('la').value,$('lo').value))return;DB.cos.push({n,lat:+$('la').value,lng:+$('lo').value});lg('Empresa registrada: '+n);sv();mapOpts()};
$('userform').addEventListener('submit',async e=>{e.preventDefault();
 const u=$('nu').value.trim().toLowerCase(),p=$('np').value,e2=$('ne');
 if(!/^[a-z0-9_]{4,20}$/.test(u)){e2.textContent='Usuario: 4-20 caracteres (letras, números, guion bajo).';return}
 if(DB.users.some(x=>x.u===u)){e2.textContent='El usuario ya existe.';return}
 if(!okPw(p)){e2.textContent='Contraseña débil: incumple la política.';return}
 DB.users.push({u,h:await H(p),r:$('nr').value});lg('Usuario creado: '+u);sv();e2.textContent='';$('nu').value=$('np').value='';users()
});
$('bc').onclick=()=>{const c='Fecha,Usuario,Evento\n'+DB.log.map(x=>[x.t,x.u,x.a].map(v=>'"'+String(v).replace(/"/g,'""')+'"').join(',')).join('\n');const a=document.createElement('a');a.href='data:text/csv;charset=utf-8,'+encodeURIComponent(c);a.download='bitacora_sdem.csv';a.click()};
seed();
