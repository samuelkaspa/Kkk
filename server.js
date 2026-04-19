// ══════════════════════════════════════════════════════════════════
//  HGM — House, Grupos, Mines  |  server.js
//  npm install express socket.io nodemailer
//  node server.js
// ══════════════════════════════════════════════════════════════════
const express    = require('express');
const http       = require('http');
const { Server } = require('socket.io');
const nodemailer = require('nodemailer');
const path       = require('path');
const crypto     = require('crypto');

const app    = express();
const server = http.createServer(app);
const io     = new Server(server, { cors: { origin: '*' } });

app.use(express.json({ limit: '25mb' }));
app.use(express.static(path.join(__dirname, 'public')));
app.get('*', (_, res) => res.sendFile(path.join(__dirname, 'public', 'index.html')));

const ADMIN_EMAIL = 'samuca25barbosa@gmail.com';
const PORT        = process.env.PORT || 3000;

const mail = nodemailer.createTransport({
  service: 'gmail',
  auth: { user: ADMIN_EMAIL, pass: process.env.GMAIL_PASS || '' }
});

const DB = { accounts:{}, husts:{}, bans:{}, sessions:{}, online:0 };

const uid    = () => crypto.randomUUID();
const sha    = pw => crypto.createHash('sha256').update(String(pw)).digest('hex');
const genCode= (n=15) => { const c='ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789'; return Array.from({length:n},()=>c[Math.random()*c.length|0]).join(''); };
const getAge = dob => { const t=new Date(),b=new Date(dob),a=t.getFullYear()-b.getFullYear(); return a-(t<new Date(t.getFullYear(),b.getMonth(),b.getDate())?1:0); };
const bySock = sid => { const id=DB.sessions[sid]; return id?DB.accounts[id]:null; };
const pubAcc = a => ({ id:a.id,name:a.name,bio:a.bio,avatar:a.avatar,isAdmin:a.isAdmin,verified:a.verified });
const isBan  = id => { const b=DB.bans[id]; if(!b) return false; if(b.permanent) return b; if(b.until>Date.now()) return b; delete DB.bans[id]; return false; };
const pubHust= (h,acc) => ({
  id:h.id, code:h.code, name:h.name, type:h.type, minAge:h.minAge,
  hasPassword:!!h.password, gameName:h.gameName, gameImage:h.gameImage,
  images:h.images, links:h.links, video:h.video,
  pinnedMessages:h.pinnedMessages, memberCount:h.members.length,
  ownerName:h.ownerName, ownerId:h.ownerId, admins:h.admins,
  createdAt:h.createdAt, muted:h.muted||{},
  isOwner:      acc ? h.ownerId===acc.id : false,
  isHustAdmin:  acc ? (h.admins||[]).some(a=>a===acc.name||a===acc.id) : false,
  isMember:     acc ? h.members.includes(acc.id) : false
});

const tv = text => io.emit('tv', { text });

io.on('connection', socket => {
  DB.online++;
  io.emit('online', DB.online);
  tv(`🟢 Alguém entrou — ${DB.online} online`);

  socket.on('disconnect', () => {
    DB.online = Math.max(0, DB.online-1);
    const acc = bySock(socket.id);
    delete DB.sessions[socket.id];
    tv(`🔴 ${acc?acc.name:'Alguém'} saiu — ${DB.online} online`);
    io.emit('online', DB.online);
  });

  /* ── AUTH ── */
  socket.on('register', ({name,bio,avatar,birthdate,email,password}, cb) => {
    if(!name||name.length<2||name.length>30) return cb({error:'Nome: 2–30 chars'});
    if(!password||password.length<6) return cb({error:'Senha mínimo 6 caracteres'});
    if(!birthdate) return cb({error:'Data de nascimento obrigatória'});
    if(getAge(birthdate)<18||getAge(birthdate)>120) return cb({error:'Precisa ter +18 anos'});
    if(bio&&bio.length>150) return cb({error:'Bio máx 150 chars'});
    const pw=sha(password);
    if(Object.values(DB.accounts).find(a=>a.passwordHash===pw)) return cb({error:'Essa senha já está em uso por outra conta'});
    if(email&&Object.values(DB.accounts).find(a=>a.email===email.toLowerCase())) return cb({error:'Email já cadastrado'});
    const id=uid();
    const acc={ id,name,bio:bio||'',avatar:avatar||null,birthdate,
      email:email?email.toLowerCase():null, passwordHash:pw,
      isAdmin:!!(email&&email.toLowerCase()===ADMIN_EMAIL),
      verified:!!(email&&email.toLowerCase()===ADMIN_EMAIL),
      createdAt:Date.now(), hustsCreated:[], hustsSaved:[] };
    DB.accounts[id]=acc; DB.sessions[socket.id]=id;
    tv(`✨ ${name} criou uma conta!`);
    cb({ok:true,account:pubAcc(acc)});
  });

  socket.on('login', ({email,password}, cb) => {
    const pw=sha(password); let acc=null;
    if(email) acc=Object.values(DB.accounts).find(a=>a.email===email.toLowerCase()&&a.passwordHash===pw);
    else      acc=Object.values(DB.accounts).find(a=>a.passwordHash===pw);
    if(!acc) return cb({error:'Conta não encontrada'});
    const ban=isBan(acc.id);
    if(ban) return cb({error:`Banido${ban.permanent?' permanentemente':''}: ${ban.reason}`});
    DB.sessions[socket.id]=acc.id;
    cb({ok:true,account:pubAcc(acc)});
  });

  socket.on('getMe',(_,cb)=>{ const a=bySock(socket.id); cb(a?{ok:true,account:pubAcc(a)}:{error:'Não autenticado'}); });

  socket.on('updateProfile', ({name,bio,avatar,currentPassword,newPassword}, cb) => {
    const acc=bySock(socket.id); if(!acc) return cb({error:'Não autenticado'});
    if(name&&(name.length<2||name.length>30)) return cb({error:'Nome 2–30 chars'});
    if(bio!==undefined&&bio.length>150) return cb({error:'Bio máx 150 chars'});
    if(newPassword){
      if(!currentPassword||acc.passwordHash!==sha(currentPassword)) return cb({error:'Senha atual incorreta'});
      if(newPassword.length<6) return cb({error:'Nova senha mín 6 chars'});
      const pw=sha(newPassword);
      if(Object.values(DB.accounts).find(a=>a.id!==acc.id&&a.passwordHash===pw)) return cb({error:'Senha já em uso'});
      acc.passwordHash=pw;
    }
    if(name) acc.name=name;
    if(bio!==undefined) acc.bio=bio;
    if(avatar!==undefined) acc.avatar=avatar;
    cb({ok:true,account:pubAcc(acc)});
  });

  socket.on('deleteAccount',({password},cb)=>{
    const acc=bySock(socket.id); if(!acc) return cb({error:'Não autenticado'});
    if(acc.passwordHash!==sha(password)) return cb({error:'Senha incorreta'});
    delete DB.accounts[acc.id]; delete DB.sessions[socket.id]; cb({ok:true});
  });

  /* ── HUSTS ── */
  socket.on('checkHustName',(name,cb)=>{
    if(!name||name.length<2) return cb({available:false,error:'Mín 2 chars'});
    if(name.length>100) return cb({available:false,error:'Máx 100 chars'});
    cb({available:!Object.values(DB.husts).find(h=>h.name.toLowerCase()===name.toLowerCase())});
  });

  socket.on('createHust',(data,cb)=>{
    const acc=bySock(socket.id); if(!acc) return cb({error:'Faça login primeiro'});
    const {name,type,minAge,password,admins,gameName,gameImage,links,images,video}=data;
    if(!name||name.length<2||name.length>100) return cb({error:'Nome inválido'});
    if(Object.values(DB.husts).find(h=>h.name.toLowerCase()===name.toLowerCase())) return cb({error:'Nome já em uso'});
    if(!['conversa','jogo','jogo+link','tudo'].includes(type)) return cb({error:'Tipo inválido'});
    if(['jogo','jogo+link','tudo'].includes(type)&&!gameName) return cb({error:'Nome do jogo obrigatório'});
    if(['jogo','tudo'].includes(type)&&!gameImage) return cb({error:'Imagem obrigatória'});
    if(type==='jogo+link'&&!links?.filter(Boolean).length) return cb({error:'Pelo menos 1 link'});
    if(type==='tudo'&&(!links?.filter(Boolean).length||!images?.filter(Boolean).length)) return cb({error:'1 link e 1 imagem obrigatórios'});
    const id=uid(), c=genCode();
    const hust={id,code:c,name,type,minAge:minAge||0,password:password||null,
      admins:admins||[],ownerId:acc.id,ownerName:acc.name,
      gameName:gameName||null,gameImage:gameImage||null,
      images:images||[],links:links||[],video:video||null,
      pinnedMessages:[],messages:[],members:[acc.id],muted:{},banned:{},createdAt:Date.now()};
    DB.husts[id]=hust; acc.hustsCreated.push(id); acc.hustsSaved.push(id);
    const hp=pubHust(hust,acc);
    io.emit('hustCreated',hp);
    tv(`🎉 Nova hust criada: "${name}"`);
    cb({ok:true,hust:hp});
  });

  socket.on('getHusts',(_,cb)=>{ const a=bySock(socket.id); cb({ok:true,husts:Object.values(DB.husts).sort((a,b)=>b.createdAt-a.createdAt).map(h=>pubHust(h,a))}); });

  socket.on('searchHust',(q,cb)=>{ const a=bySock(socket.id),ql=(q||'').toLowerCase().trim(); cb({ok:true,husts:Object.values(DB.husts).filter(h=>h.name.toLowerCase().includes(ql)||h.code.toLowerCase().includes(ql)).map(h=>pubHust(h,a))}); });

  socket.on('getMyHusts',(_,cb)=>{
    const acc=bySock(socket.id); if(!acc) return cb({error:'Não autenticado'});
    cb({ok:true,
      created:(acc.hustsCreated||[]).map(id=>DB.husts[id]).filter(Boolean).map(h=>pubHust(h,acc)),
      saved:(acc.hustsSaved||[]).map(id=>DB.husts[id]).filter(Boolean).map(h=>pubHust(h,acc))});
  });

  socket.on('enterHust',({hustId,password},cb)=>{
    const acc=bySock(socket.id);
    const hust=DB.husts[hustId]; if(!hust) return cb({error:'Hust não encontrada'});
    if(acc){ const ban=hust.banned[acc.id]; if(ban&&(ban.permanent||ban.until>Date.now())) return cb({error:`Banido: ${ban.reason}`}); }
    if(acc&&hust.minAge>0&&getAge(acc.birthdate)<hust.minAge) return cb({error:`+${hust.minAge} anos necessários`});
    if(hust.password&&hust.password!==password) return cb({error:'Senha incorreta'});
    if(acc&&!hust.members.includes(acc.id)) hust.members.push(acc.id);
    if(acc&&!acc.hustsSaved.includes(hustId)) acc.hustsSaved.push(hustId);
    socket.join(`h:${hustId}`);
    const hp=pubHust(hust,acc);
    io.to(`h:${hustId}`).emit('hustUpdate',hp);
    cb({ok:true,hust:hp,messages:hust.messages.slice(-120)});
  });

  socket.on('leaveHust',(id,cb)=>{ socket.leave(`h:${id}`); cb&&cb({ok:true}); });

  socket.on('sendMessage',({hustId,text},cb)=>{
    const acc=bySock(socket.id); if(!acc) return cb&&cb({error:'Não autenticado'});
    const hust=DB.husts[hustId]; if(!hust) return cb&&cb({error:'Hust não encontrada'});
    if(!text?.trim()) return cb&&cb({error:'Vazio'});
    const isO=hust.ownerId===acc.id, isA=(hust.admins||[]).some(a=>a===acc.name||a===acc.id);
    if(!isO&&!isA&&!acc.isAdmin&&/https?:\/\//i.test(text)) return cb&&cb({error:'Links bloqueados para membros'});
    const mut=hust.muted[acc.id];
    if(mut&&(mut.permanent||mut.until>Date.now())) return cb&&cb({error:'Você está silenciado'});
    const msg={id:uid(),hustId,senderId:acc.id,senderName:acc.name,senderAvatar:acc.avatar,
      isOwner:isO,isHustAdmin:isA,isSiteAdmin:acc.isAdmin,text:text.trim(),ts:Date.now()};
    hust.messages.push(msg); if(hust.messages.length>600) hust.messages=hust.messages.slice(-600);
    io.to(`h:${hustId}`).emit('msg',msg); cb&&cb({ok:true});
  });

  socket.on('pinMessage',({hustId,text},cb)=>{
    const acc=bySock(socket.id); if(!acc) return cb({error:'Não autenticado'});
    const hust=DB.husts[hustId]; if(!hust||(hust.ownerId!==acc.id&&!acc.isAdmin)) return cb({error:'Sem permissão'});
    if(hust.pinnedMessages.length>=5) return cb({error:'Máx 5 mensagens fixas'});
    hust.pinnedMessages.push({id:uid(),text,at:Date.now()});
    io.to(`h:${hustId}`).emit('hustUpdate',pubHust(hust,acc)); cb({ok:true});
  });

  socket.on('unpinMessage',({hustId,pinId},cb)=>{
    const acc=bySock(socket.id); if(!acc) return cb({error:'Não autenticado'});
    const hust=DB.husts[hustId]; if(!hust||(hust.ownerId!==acc.id&&!acc.isAdmin)) return cb({error:'Sem permissão'});
    hust.pinnedMessages=hust.pinnedMessages.filter(p=>p.id!==pinId);
    io.to(`h:${hustId}`).emit('hustUpdate',pubHust(hust,acc)); cb({ok:true});
  });

  socket.on('editHust',(data,cb)=>{
    const acc=bySock(socket.id); if(!acc) return cb({error:'Não autenticado'});
    const hust=DB.husts[data.hustId]; if(!hust||(hust.ownerId!==acc.id&&!acc.isAdmin)) return cb({error:'Sem permissão'});
    if(data.name&&data.name!==hust.name){
      if(data.name.length<2||data.name.length>100) return cb({error:'Nome inválido'});
      if(Object.values(DB.husts).find(h=>h.id!==data.hustId&&h.name.toLowerCase()===data.name.toLowerCase())) return cb({error:'Nome já em uso'});
      hust.name=data.name;
    }
    if(data.links) hust.links=data.links; if(data.images) hust.images=data.images; if(data.video!==undefined) hust.video=data.video;
    io.to(`h:${hust.id}`).emit('hustUpdate',pubHust(hust,acc)); cb({ok:true});
  });

  socket.on('deleteHust',(hustId,cb)=>{
    const acc=bySock(socket.id); if(!acc) return cb({error:'Não autenticado'});
    const hust=DB.husts[hustId]; if(!hust||(hust.ownerId!==acc.id&&!acc.isAdmin)) return cb({error:'Sem permissão'});
    delete DB.husts[hustId]; io.emit('hustDeleted',hustId); cb({ok:true});
  });

  /* ── MODERAÇÃO ── */
  socket.on('muteUser',({hustId,targetId,permanent,durationMs},cb)=>{
    const acc=bySock(socket.id); if(!acc) return cb({error:'Não autenticado'});
    const hust=DB.husts[hustId]; if(!hust) return cb({error:'Não encontrada'});
    const ok=hust.ownerId===acc.id||(hust.admins||[]).some(a=>a===acc.name||a===acc.id)||acc.isAdmin;
    if(!ok) return cb({error:'Sem permissão'});
    hust.muted[targetId]={permanent:!!permanent,until:permanent?null:Date.now()+(durationMs||0)};
    io.to(`h:${hustId}`).emit('muted',{targetId,permanent,until:hust.muted[targetId].until}); cb({ok:true});
  });

  socket.on('unmuteUser',({hustId,targetId},cb)=>{
    const acc=bySock(socket.id); if(!acc) return cb({error:'Não autenticado'});
    const hust=DB.husts[hustId]; if(!hust) return cb({error:'Não encontrada'});
    const ok=hust.ownerId===acc.id||(hust.admins||[]).some(a=>a===acc.name||a===acc.id)||acc.isAdmin;
    if(!ok) return cb({error:'Sem permissão'}); delete hust.muted[targetId];
    io.to(`h:${hustId}`).emit('unmuted',{targetId}); cb({ok:true});
  });

  socket.on('hustBan',({hustId,targetId,reason,permanent,durationMs},cb)=>{
    const acc=bySock(socket.id); if(!acc) return cb({error:'Não autenticado'});
    const hust=DB.husts[hustId]; if(!hust) return cb({error:'Não encontrada'});
    if(hust.ownerId!==acc.id&&!acc.isAdmin) return cb({error:'Sem permissão'});
    hust.banned[targetId]={reason:reason||'Sem motivo',permanent:!!permanent,until:Date.now()+(durationMs||0)};
    hust.members=hust.members.filter(m=>m!==targetId);
    io.to(`h:${hustId}`).emit('hustBanned',{targetId,reason,hustId});
    io.to(`h:${hustId}`).emit('hustUpdate',pubHust(hust,acc)); cb({ok:true});
  });

  socket.on('adminBan',({targetId,reason,permanent,durationMs},cb)=>{
    const acc=bySock(socket.id); if(!acc?.isAdmin) return cb({error:'Sem permissão'});
    DB.bans[targetId]={reason,permanent:!!permanent,until:Date.now()+(durationMs||0)};
    tv(`🚫 Usuário banido pelo administrador.`); cb({ok:true});
  });

  socket.on('adminGetAccounts',(_,cb)=>{
    const acc=bySock(socket.id); if(!acc?.isAdmin) return cb({error:'Sem permissão'});
    cb({ok:true,accounts:Object.values(DB.accounts).map(a=>({id:a.id,name:a.name,email:a.email,isAdmin:a.isAdmin,createdAt:a.createdAt,hustsCreated:a.hustsCreated?.length||0,banned:!!DB.bans[a.id]}))});
  });

  socket.on('adminSetAdmin',({targetId,value},cb)=>{
    const acc=bySock(socket.id); if(!acc?.isAdmin) return cb({error:'Sem permissão'});
    const t=DB.accounts[targetId]; if(!t) return cb({error:'Não encontrado'});
    t.isAdmin=!!value; t.verified=!!value; cb({ok:true});
  });

  socket.on('report',async({hustId,reason},cb)=>{
    const acc=bySock(socket.id);
    const hust=DB.husts[hustId]; if(!hust) return cb({error:'Hust não encontrada'});
    try{ await mail.sendMail({from:ADMIN_EMAIL,to:ADMIN_EMAIL,subject:`[REPORT] ${hust.name}`,
      html:`<h2>Report</h2><b>Hust:</b> ${hust.name}<br><b>Código:</b> ${hust.code}<br><b>Criador:</b> ${hust.ownerName}<br><b>Por:</b> ${acc?acc.name:'Convidado'}<br><b>Motivo:</b><p>${reason}</p>`});
    }catch(e){console.error('Mail error:',e.message);}
    cb({ok:true});
  });
});

server.listen(PORT,()=>console.log(`🚀 HGM em http://localhost:${PORT}`));
