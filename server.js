import express from "express";
import Database from "better-sqlite3";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";

const app=express(), db=new Database("social.db");
const SECRET=process.env.JWT_SECRET||"change-this-secret";
app.use(express.json({limit:"2mb"}));

db.exec(`
CREATE TABLE IF NOT EXISTS users(
 id INTEGER PRIMARY KEY AUTOINCREMENT,username TEXT UNIQUE,name TEXT,password TEXT,
 avatar TEXT DEFAULT '',bio TEXT DEFAULT '',created_at TEXT DEFAULT CURRENT_TIMESTAMP);
CREATE TABLE IF NOT EXISTS posts(
 id INTEGER PRIMARY KEY AUTOINCREMENT,user_id INTEGER,content TEXT,image TEXT,
 created_at TEXT DEFAULT CURRENT_TIMESTAMP);
CREATE TABLE IF NOT EXISTS likes(user_id INTEGER,post_id INTEGER,PRIMARY KEY(user_id,post_id));
CREATE TABLE IF NOT EXISTS comments(
 id INTEGER PRIMARY KEY AUTOINCREMENT,user_id INTEGER,post_id INTEGER,content TEXT,
 created_at TEXT DEFAULT CURRENT_TIMESTAMP);
CREATE TABLE IF NOT EXISTS follows(follower_id INTEGER,following_id INTEGER,
 PRIMARY KEY(follower_id,following_id));
`);

const user=id=>db.prepare("SELECT id,username,name,avatar,bio,created_at FROM users WHERE id=?").get(id);
function auth(req,res,next){
 const t=(req.headers.authorization||"").replace("Bearer ","");
 try{req.user=jwt.verify(t,SECRET);next()}catch{res.status(401).json({error:"غير مسجل الدخول"})}
}

app.post("/api/register",(req,res)=>{
 const {name,username,password}=req.body;
 if(!name||!username||!password||password.length<6)return res.status(400).json({error:"أدخل البيانات كاملة وكلمة المرور 6 أحرف على الأقل"});
 try{
  const id=db.prepare("INSERT INTO users(name,username,password) VALUES(?,?,?)").run(name,username.toLowerCase(),bcrypt.hashSync(password,10)).lastInsertRowid;
  const u=user(id);res.json({token:jwt.sign({id},SECRET,{expiresIn:"30d"}),user:u});
 }catch{res.status(400).json({error:"اسم المستخدم مستخدم بالفعل"})}
});
app.post("/api/login",(req,res)=>{
 const u=db.prepare("SELECT * FROM users WHERE username=?").get((req.body.username||"").toLowerCase());
 if(!u||!bcrypt.compareSync(req.body.password||"",u.password))return res.status(401).json({error:"بيانات الدخول غير صحيحة"});
 res.json({token:jwt.sign({id:u.id},SECRET,{expiresIn:"30d"}),user:user(u.id)});
});
app.get("/api/me",auth,(req,res)=>res.json(user(req.user.id)));
app.put("/api/me",auth,(req,res)=>{
 const {name,bio,avatar}=req.body;
 db.prepare("UPDATE users SET name=COALESCE(?,name),bio=COALESCE(?,bio),avatar=COALESCE(?,avatar) WHERE id=?").run(name,bio,avatar,req.user.id);
 res.json(user(req.user.id));
});
app.post("/api/posts",auth,(req,res)=>{
 const {content="",image=""}=req.body;
 if(!content.trim()&&!image)return res.status(400).json({error:"المنشور فارغ"});
 res.json({id:db.prepare("INSERT INTO posts(user_id,content,image) VALUES(?,?,?)").run(req.user.id,content.trim(),image).lastInsertRowid});
});
app.get("/api/feed",auth,(req,res)=>{
 res.json(db.prepare(`SELECT p.*,u.username,u.name,u.avatar,
 (SELECT COUNT(*) FROM likes WHERE post_id=p.id) likes,
 (SELECT COUNT(*) FROM comments WHERE post_id=p.id) comments,
 EXISTS(SELECT 1 FROM likes WHERE post_id=p.id AND user_id=?) liked
 FROM posts p JOIN users u ON u.id=p.user_id
 WHERE p.user_id=? OR p.user_id IN(SELECT following_id FROM follows WHERE follower_id=?)
 ORDER BY p.created_at DESC`).all(req.user.id,req.user.id,req.user.id));
});
app.post("/api/posts/:id/like",auth,(req,res)=>{
 const id=+req.params.id, x=db.prepare("SELECT 1 FROM likes WHERE user_id=? AND post_id=?").get(req.user.id,id);
 if(x){db.prepare("DELETE FROM likes WHERE user_id=? AND post_id=?").run(req.user.id,id);res.json({liked:false})}
 else{db.prepare("INSERT INTO likes VALUES(?,?)").run(req.user.id,id);res.json({liked:true})}
});
app.get("/api/posts/:id/comments",auth,(req,res)=>res.json(
 db.prepare("SELECT c.*,u.name,u.username,u.avatar FROM comments c JOIN users u ON u.id=c.user_id WHERE post_id=? ORDER BY c.created_at").all(req.params.id)));
app.post("/api/posts/:id/comments",auth,(req,res)=>{
 const c=(req.body.content||"").trim();if(!c)return res.status(400).json({error:"التعليق فارغ"});
 db.prepare("INSERT INTO comments(user_id,post_id,content) VALUES(?,?,?)").run(req.user.id,req.params.id,c);res.json({ok:true});
});
app.get("/api/users",auth,(req,res)=>{
 const q="%"+(req.query.q||"").trim()+"%";
 res.json(db.prepare("SELECT id,username,name,avatar,bio FROM users WHERE name LIKE ? OR username LIKE ? LIMIT 30").all(q,q));
});
app.get("/api/users/:username",auth,(req,res)=>{
 const u=db.prepare("SELECT id,username,name,avatar,bio,created_at FROM users WHERE username=?").get(req.params.username);
 if(!u)return res.status(404).json({error:"المستخدم غير موجود"});
 res.json({...u,followers:db.prepare("SELECT COUNT(*) n FROM follows WHERE following_id=?").get(u.id).n,
 following:db.prepare("SELECT COUNT(*) n FROM follows WHERE follower_id=?").get(u.id).n,
 isFollowing:!!db.prepare("SELECT 1 FROM follows WHERE follower_id=? AND following_id=?").get(req.user.id,u.id)});
});
app.post("/api/users/:id/follow",auth,(req,res)=>{
 const id=+req.params.id;
 if(id===req.user.id)return res.status(400).json({error:"لا يمكنك متابعة نفسك"});
 const x=db.prepare("SELECT 1 FROM follows WHERE follower_id=? AND following_id=?").get(req.user.id,id);
 if(x)db.prepare("DELETE FROM follows WHERE follower_id=? AND following_id=?").run(req.user.id,id);
 else db.prepare("INSERT INTO follows VALUES(?,?)").run(req.user.id,id);
 res.json({following:!x});
});
app.get("/api/users/:username/posts",auth,(req,res)=>{
 const u=db.prepare("SELECT id FROM users WHERE username=?").get(req.params.username);
 if(!u)return res.status(404).json({error:"المستخدم غير موجود"});
 res.json(db.prepare(`SELECT p.*,u.username,u.name,u.avatar,
 (SELECT COUNT(*) FROM likes WHERE post_id=p.id) likes,
 (SELECT COUNT(*) FROM comments WHERE post_id=p.id) comments,
 EXISTS(SELECT 1 FROM likes WHERE post_id=p.id AND user_id=?) liked
 FROM posts p JOIN users u ON u.id=p.user_id WHERE p.user_id=? ORDER BY p.created_at DESC`).all(req.user.id,u.id));
});

const html=`<!doctype html><html lang="ar" dir="rtl"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>شبكتي</title>
<style>
*{box-sizing:border-box}body{margin:0;font-family:Arial,Tahoma;background:#f0f2f5;color:#172033}button,input,textarea{font:inherit}button{border:0;cursor:pointer}.top{height:60px;background:white;display:flex;align-items:center;gap:10px;padding:8px 15px;position:sticky;top:0;z-index:5;border-bottom:1px solid #ddd}.logo{font-size:24px;font-weight:bold;color:#1877f2}.search{flex:1;max-width:430px;padding:10px 15px;border:0;background:#f0f2f5;border-radius:22px;outline:0}.layout{max-width:1050px;margin:18px auto;display:grid;grid-template-columns:220px 1fr 220px;gap:15px}.card{background:#fff;border-radius:14px;padding:15px;margin-bottom:14px;box-shadow:0 1px 3px #0001}.avatar{width:44px;height:44px;border-radius:50%;object-fit:cover;background:#dbeafe;display:grid;place-items:center;color:#1877f2;font-weight:bold}.row{display:flex;align-items:center;gap:9px}.between{justify-content:space-between}.muted{color:#667085;font-size:13px}.name{font-weight:bold;color:#172033}.btn{padding:9px 13px;border-radius:9px;background:#e4e6eb}.primary{background:#1877f2;color:#fff}.composer textarea{width:100%;margin:12px 0;min-height:85px;border:0;border-radius:12px;background:#f0f2f5;padding:12px;outline:0}.post-head{display:flex;gap:9px}.post-content{white-space:pre-wrap;line-height:1.7;margin:12px 0}.post-image{max-width:100%;max-height:500px;border-radius:10px}.stats{display:flex;justify-content:space-between;padding:8px 0;color:#667085;border-bottom:1px solid #eee}.actions{display:grid;grid-template-columns:1fr 1fr}.actions button{background:white;padding:10px}.liked{color:#1877f2!important;font-weight:bold}.comment{padding:7px 0}.commentbox{display:flex;gap:6px;margin-top:8px}.commentbox input{flex:1;border:0;background:#f0f2f5;border-radius:20px;padding:9px}.auth{min-height:100vh;display:grid;place-items:center}.authbox{width:min(420px,92%);background:#fff;padding:25px;border-radius:18px}.authbox input{width:100%;padding:12px;margin:5px 0;border:1px solid #ddd;border-radius:9px}.authbox button{width:100%;padding:12px;margin-top:8px}@media(max-width:850px){.layout{display:block;max-width:650px;padding:0 10px}.side{display:none}.top{padding:8px}.search{max-width:none}}
</style></head><body><div id="app"></div><script>
let token=localStorage.getItem("token"),me=null,$=s=>document.querySelector(s);
const esc=s=>String(s??"").replace(/[&<>"']/g,c=>({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[c]));
const av=u=>u.avatar?'<img class="avatar" src="'+esc(u.avatar)+'">':'<div class="avatar">'+esc((u.name||"?")[0])+'</div>';
async function api(u,o={}){o.headers={...(o.headers||{}),"Content-Type":"application/json",...(token?{Authorization:"Bearer "+token}:{})};let r=await fetch(u,o),d=await r.json();if(!r.ok)throw Error(d.error||"خطأ");return d}
function auth(){app.innerHTML='<div class="auth"><div class="authbox"><h1 class="logo">شبكتي</h1><input id="n" placeholder="الاسم"><input id="u" placeholder="اسم المستخدم"><input id="p" type="password" placeholder="كلمة المرور"><button class="btn primary" onclick="reg()">إنشاء حساب</button><hr><button class="btn" onclick="login()">تسجيل الدخول</button></div></div>'}
async function reg(){try{let d=await api("/api/register",{method:"POST",body:JSON.stringify({name:n.value,username:u.value,password:p.value})});token=d.token;localStorage.token=token;start()}catch(e){alert(e.message)}}
async function login(){try{let d=await api("/api/login",{method:"POST",body:JSON.stringify({username:u.value,password:p.value})});token=d.token;localStorage.token=token;start()}catch(e){alert(e.message)}}
function shell(){app.innerHTML='<header class="top"><b class="logo">شبكتي</b><input class="search" id="q" placeholder="ابحث عن مستخدم واضغط Enter"><button class="btn" onclick="logout()">خروج</button></header><main class="layout"><aside class="side"><div class="card">'+av(me)+'<b>'+esc(me.name)+'</b><div class="muted">@'+esc(me.username)+'</div></div><div class="card"><button class="btn" onclick="feed()">🏠 الرئيسية</button><br><br><button class="btn" onclick="profile(me.username)">👤 ملفي</button></div></aside><section id="view"></section><aside class="side"><div class="card"><b>شبكتي</b><p class="muted">انشر وتابع أصدقاءك.</p></div></aside></main>';q.onkeydown=e=>{if(e.key==="Enter")search(q.value)}}
function composer(){return '<div class="card composer"><div class="row">'+av(me)+'<b>'+esc(me.name)+'</b></div><textarea id="pc" placeholder="بماذا تفكر؟"></textarea><input class="search" style="width:100%" id="pi" placeholder="رابط صورة اختياري"><button class="btn primary" style="margin-top:8px" onclick="publish()">نشر</button></div>'}
function post(p){return '<article class="card"><div class="post-head">'+av(p)+'<div><b>'+esc(p.name)+'</b><div class="muted">@'+esc(p.username)+' · '+esc(p.created_at)+'</div></div></div>'+(p.content?'<div class="post-content">'+esc(p.content)+'</div>':'')+(p.image?'<img class="post-image" src="'+esc(p.image)+'">':'')+'<div class="stats"><span>❤️ '+p.likes+'</span><span>💬 '+p.comments+'</span></div><div class="actions"><button class="'+(p.liked?"liked":"")+'" onclick="like('+p.id+')">❤️ إعجاب</button><button onclick="comments('+p.id+')">💬 تعليقات</button></div><div id="c'+p.id+'"></div></article>'}
async function feed(){view.innerHTML=composer()+"<div id='posts'>جاري التحميل...</div>";let ps=await api("/api/feed");posts.innerHTML=ps.map(post).join("")||'<div class="card">لا توجد منشورات بعد.</div>'}
async function publish(){try{await api("/api/posts",{method:"POST",body:JSON.stringify({content:pc.value,image:pi.value})});feed()}catch(e){alert(e.message)}}
async function like(id){await api("/api/posts/"+id+"/like",{method:"POST"});feed()}
async function comments(id){let b=$("#c"+id);if(b.innerHTML){b.innerHTML="";return}let cs=await api("/api/posts/"+id+"/comments");b.innerHTML=cs.map(c=>'<div class="comment"><b>'+esc(c.name)+'</b>: '+esc(c.content)+'</div>').join("")+'<div class="commentbox"><input id="i'+id+'" placeholder="تعليق..."><button class="btn primary" onclick="addc('+id+')">إرسال</button></div>'}
async function addc(id){await api("/api/posts/"+id+"/comments",{method:"POST",body:JSON.stringify({content:$("#i"+id).value})});comments(id)}
async function profile(username){let u=await api("/api/users/"+username),ps=await api("/api/users/"+username+"/posts");view.innerHTML='<div class="card"><div class="row">'+av(u)+'<div><h2>'+esc(u.name)+'</h2><div class="muted">@'+esc(u.username)+'</div></div></div><p>'+esc(u.bio||"لا توجد نبذة")+'</p><p class="muted">👥 '+u.followers+' متابع · يتابع '+u.following+'</p>'+(u.id!=me.id?'<button class="btn primary" onclick="follow('+u.id+',\\''+esc(u.username)+'\\')">'+(u.isFollowing?"إلغاء المتابعة":"متابعة")+'</button>':"")+'</div>'+ps.map(post).join("")}
async function follow(id,u){await api("/api/users/"+id+"/follow",{method:"POST"});profile(u)}
async function search(q){let us=await api("/api/users?q="+encodeURIComponent(q));view.innerHTML='<div class="card"><h3>نتائج البحث</h3>'+us.map(u=>'<div class="row" style="padding:10px 0"><a href="#" onclick="profile(\\''+esc(u.username)+'\\');return false">'+av(u)+'</a><b>'+esc(u.name)+'</b><span class="muted">@'+esc(u.username)+'</span></div>').join("")+'</div>'}
function logout(){localStorage.removeItem("token");token=null;auth()}
async function start(){try{me=await api("/api/me");shell();feed()}catch{logout()}}
if(token)start();else auth();
</script></body></html>`;

app.get("*",(req,res)=>res.type("html").send(html));
app.listen(process.env.PORT||3000,()=>console.log("running"));
