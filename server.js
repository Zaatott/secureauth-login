const express=require("express");
const session=require("express-session");
const bcrypt=require("bcryptjs");
const helmet=require("helmet");
const rateLimit=require("express-rate-limit");
const path=require("path"),fs=require("fs");
const app=express(),PORT=Number(process.env.PORT||3000);
const ROOT=__dirname,DATA=path.join(ROOT,"data"),ONLINE=!!process.env.DATABASE_URL;
let db,pool,Store;
if(!ONLINE){
 if(!fs.existsSync(DATA))fs.mkdirSync(DATA,{recursive:true});
 const Database=require("better-sqlite3"),sqlite=new Database(path.join(DATA,"users.db"));
 sqlite.pragma("journal_mode=WAL");
 sqlite.exec(`CREATE TABLE IF NOT EXISTS users(
 id INTEGER PRIMARY KEY AUTOINCREMENT,username TEXT NOT NULL UNIQUE COLLATE NOCASE,
 email TEXT NOT NULL UNIQUE COLLATE NOCASE,password TEXT NOT NULL,
 role TEXT NOT NULL DEFAULT 'user' CHECK(role IN ('user','admin')),
 created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,last_login TEXT)`);
 db={
 init:async()=>{},
 get:async id=>sqlite.prepare("SELECT id,username,email,role,created_at,last_login,password FROM users WHERE id=?").get(id),
 identity:async x=>sqlite.prepare("SELECT * FROM users WHERE username=? COLLATE NOCASE OR email=? COLLATE NOCASE LIMIT 1").get(x,x),
 exists:async(u,e)=>sqlite.prepare("SELECT id FROM users WHERE username=? COLLATE NOCASE OR email=? COLLATE NOCASE LIMIT 1").get(u,e),
 add:async(u,e,p,r="user")=>{let h=await bcrypt.hash(p,12);return sqlite.prepare("INSERT INTO users(username,email,password,role) VALUES(?,?,?,?)").run(u,e,h,r).lastInsertRowid},
 all:async()=>sqlite.prepare("SELECT id,username,email,role,created_at,last_login FROM users ORDER BY id DESC").all(),
 del:async id=>sqlite.prepare("DELETE FROM users WHERE id=?").run(id).changes,
 last:async id=>sqlite.prepare("UPDATE users SET last_login=CURRENT_TIMESTAMP WHERE id=?").run(id),
 pass:async id=>sqlite.prepare("SELECT password FROM users WHERE id=?").get(id),
 change:async(id,h)=>sqlite.prepare("UPDATE users SET password=? WHERE id=?").run(h,id)
 };
 Store=require("connect-sqlite3")(session);
}else{
 const {Pool}=require("pg");pool=new Pool({connectionString:process.env.DATABASE_URL,ssl:{rejectUnauthorized:false},max:10});
 db={
 init:async()=>pool.query(`CREATE TABLE IF NOT EXISTS users(
 id SERIAL PRIMARY KEY,username TEXT NOT NULL UNIQUE,email TEXT NOT NULL UNIQUE,password TEXT NOT NULL,
 role TEXT NOT NULL DEFAULT 'user' CHECK(role IN ('user','admin')),created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),last_login TIMESTAMPTZ)`),
 get:async id=>(await pool.query("SELECT id,username,email,role,created_at,last_login,password FROM users WHERE id=$1",[id])).rows[0],
 identity:async x=>(await pool.query("SELECT * FROM users WHERE LOWER(username)=LOWER($1) OR LOWER(email)=LOWER($1) LIMIT 1",[x])).rows[0],
 exists:async(u,e)=>(await pool.query("SELECT id FROM users WHERE LOWER(username)=LOWER($1) OR LOWER(email)=LOWER($2) LIMIT 1",[u,e])).rows[0],
 add:async(u,e,p,r="user")=>{let h=await bcrypt.hash(p,12);return(await pool.query("INSERT INTO users(username,email,password,role) VALUES($1,$2,$3,$4) RETURNING id",[u,e,h,r])).rows[0].id},
 all:async()=>(await pool.query("SELECT id,username,email,role,created_at,last_login FROM users ORDER BY id DESC")).rows,
 del:async id=>(await pool.query("DELETE FROM users WHERE id=$1",[id])).rowCount,
 last:async id=>pool.query("UPDATE users SET last_login=NOW() WHERE id=$1",[id]),
 pass:async id=>(await pool.query("SELECT password FROM users WHERE id=$1",[id])).rows[0],
 change:async(id,h)=>pool.query("UPDATE users SET password=$1 WHERE id=$2",[h,id])
 };
 Store=require("connect-pg-simple")(session);
}
const so={secret:process.env.SESSION_SECRET||"local-dev-secret",resave:false,saveUninitialized:false,cookie:{httpOnly:true,sameSite:"lax",secure:process.env.NODE_ENV==="production",maxAge:86400000},store:ONLINE?new Store({pool,createTableIfMissing:true}):new Store({db:"sessions.db",dir:DATA})};
app.use(helmet({contentSecurityPolicy:false}));app.use(express.json({limit:"20kb"}));app.use(session(so));
const limiter=rateLimit({windowMs:900000,limit:10,standardHeaders:true,legacyHeaders:false,message:{ok:false,message:"Terlalu banyak percobaan login. Coba lagi nanti."}});
const clean=x=>String(x??"").trim(), validU=x=>/^[a-zA-Z0-9_.-]{3,24}$/.test(x),validE=x=>/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(x),validP=x=>typeof x==="string"&&x.length>=8&&x.length<=128;
const auth=(q,s,n)=>q.session.user?n():s.status(401).json({ok:false,message:"Anda harus login."});
const admin=(q,s,n)=>q.session.user?.role==="admin"?n():s.status(403).json({ok:false,message:"Akses admin ditolak."});
app.post("/api/register",async(q,s)=>{try{let u=clean(q.body.username),e=clean(q.body.email).toLowerCase(),p=q.body.password;if(!validU(u))return s.status(400).json({ok:false,message:"Username 3–24 karakter dan hanya boleh huruf, angka, titik, underscore, atau strip."});if(!validE(e))return s.status(400).json({ok:false,message:"Format email tidak valid."});if(!validP(p))return s.status(400).json({ok:false,message:"Password minimal 8 karakter."});if(await db.exists(u,e))return s.status(409).json({ok:false,message:"Username atau email sudah digunakan."});let id=await db.add(u,e,p);s.status(201).json({ok:true,message:"Registrasi berhasil. Silakan login.",userId:id})}catch(e){console.error(e);s.status(500).json({ok:false,message:"Terjadi kesalahan server."})}});
app.post("/api/login",limiter,async(q,s)=>{try{let x=clean(q.body.identity),p=q.body.password;if(!x||!p)return s.status(400).json({ok:false,message:"Username/email dan password wajib diisi."});let u=await db.identity(x);if(!u||!(await bcrypt.compare(p,u.password)))return s.status(401).json({ok:false,message:"Username/email atau password salah."});s.regenerate(async er=>{if(er)return s.status(500).json({ok:false,message:"Gagal membuat sesi."});q.session.user={id:u.id,username:u.username,email:u.email,role:u.role};q.session.cookie.maxAge=q.body.remember?2592000000:86400000;await db.last(u.id);s.json({ok:true,message:"Login berhasil.",redirect:u.role==="admin"?"/admin.html":"/dashboard.html"})})}catch(e){console.error(e);s.status(500).json({ok:false,message:"Terjadi kesalahan server."})}});
app.post("/api/logout",(q,s)=>q.session.destroy(()=>{s.clearCookie("connect.sid");s.json({ok:true})}));
app.get("/api/me",auth,async(q,s)=>{let u=await db.get(q.session.user.id);if(!u)return s.status(401).json({ok:false});delete u.password;s.json({ok:true,user:u})});
app.get("/api/users",admin,async(q,s)=>s.json({ok:true,users:await db.all()}));
app.delete("/api/users/:id",admin,async(q,s)=>{let id=Number(q.params.id);if(id===q.session.user.id)return s.status(400).json({ok:false,message:"Tidak dapat menghapus akun sendiri."});let n=await db.del(id);s.json({ok:n>0,message:n?"User dihapus.":"User tidak ditemukan."})});
app.put("/api/change-password",auth,async(q,s)=>{let u=await db.pass(q.session.user.id);if(!u||!(await bcrypt.compare(q.body.currentPassword,u.password)))return s.status(401).json({ok:false,message:"Password lama salah."});if(!validP(q.body.newPassword))return s.status(400).json({ok:false,message:"Password baru minimal 8 karakter."});await db.change(q.session.user.id,await bcrypt.hash(q.body.newPassword,12));s.json({ok:true,message:"Password berhasil diganti."})});
app.get("/api/health",(q,s)=>s.json({ok:true,database:ONLINE?"postgresql":"sqlite"}));
app.use(express.static(path.join(ROOT,"public")));app.use((q,s)=>s.status(404).sendFile(path.join(ROOT,"public","404.html")));
(async()=>{await db.init();let admins=(await db.all()).find(x=>x.role==="admin");if(!admins)await db.add(process.env.ADMIN_USERNAME||"admin",process.env.ADMIN_EMAIL||"admin@example.com",process.env.ADMIN_PASSWORD||"Admin123!","admin");app.listen(PORT,"0.0.0.0",()=>console.log(`SecureAuth running on ${PORT} using ${ONLINE?"PostgreSQL":"SQLite"}`))})().catch(e=>{console.error(e);process.exit(1)});
