import express from "express";
import path from "path";
import fs from "fs";
import crypto from "crypto";
import jwt from "jsonwebtoken";
import bcrypt from "bcryptjs";
import cookieParser from "cookie-parser";
import rateLimit from "express-rate-limit";
import multer from "multer";
import slugify from "slugify";
import Database from "better-sqlite3";

const app = express();
const PORT = Number(process.env.PORT || 3000);
const ROOT = process.cwd();
const DB_FILE = process.env.DB_FILE || path.join(ROOT,"data","aura.db");
const UPLOAD_DIR = process.env.UPLOAD_DIR || path.join(ROOT,"uploads");
const JWT_SECRET = process.env.JWT_SECRET || "CHANGE_THIS_SECRET";
const ADMIN_EMAIL = process.env.ADMIN_EMAIL || "admin@example.com";
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || "change-me";

fs.mkdirSync(path.dirname(DB_FILE), {recursive:true});
fs.mkdirSync(UPLOAD_DIR, {recursive:true});

const db = new Database(DB_FILE);
db.pragma("journal_mode = WAL");
db.exec(`
CREATE TABLE IF NOT EXISTS properties (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  slug TEXT UNIQUE NOT NULL,
  name TEXT NOT NULL,
  type TEXT NOT NULL,
  price TEXT NOT NULL,
  beds INTEGER NOT NULL,
  baths INTEGER NOT NULL,
  area TEXT NOT NULL,
  description TEXT NOT NULL,
  overview TEXT NOT NULL,
  image_url TEXT,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS leads (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT NOT NULL,
  email TEXT NOT NULL,
  phone TEXT,
  message TEXT NOT NULL,
  property_id INTEGER,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY(property_id) REFERENCES properties(id) ON DELETE SET NULL
);
CREATE TABLE IF NOT EXISTS page_views (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  page TEXT NOT NULL,
  property_id INTEGER,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY(property_id) REFERENCES properties(id) ON DELETE SET NULL
);
`);

function seed(){
  if(db.prepare("SELECT COUNT(*) c FROM properties").get().c) return;
  const insert=db.prepare(`INSERT INTO properties
    (slug,name,type,price,beds,baths,area,description,overview,image_url)
    VALUES (@slug,@name,@type,@price,@beds,@baths,@area,@description,@overview,@image_url)`);
  const demo=[
    {slug:"grand-horizon",name:"The Grand Horizon",type:"Luxury Villa",price:"₹4.50 Cr",beds:4,baths:5,area:"4,800 sq.ft.",description:"A statement residence created for exceptional living.",overview:"The Grand Horizon combines sophisticated architecture with generous living spaces, refined finishes and a private environment designed for timeless comfort.",image_url:"https://images.unsplash.com/photo-1600585154340-be6161a56a0c?auto=format&fit=crop&w=1200&q=85"},
    {slug:"aura-heights",name:"Aura Heights",type:"Modern Residence",price:"₹2.50 Cr",beds:3,baths:4,area:"3,200 sq.ft.",description:"A contemporary residence designed for elevated everyday living.",overview:"Aura Heights combines contemporary architecture, refined interiors and thoughtfully designed spaces to create a sophisticated residential experience.",image_url:"https://images.unsplash.com/photo-1600607687920-4e2a09cf159d?auto=format&fit=crop&w=1200&q=85"},
    {slug:"serenity",name:"The Serenity",type:"Private Estate",price:"₹6.50 Cr",beds:5,baths:6,area:"6,100 sq.ft.",description:"A private estate where space, tranquillity and elegance meet.",overview:"The Serenity offers a generous private residence created for relaxed and sophisticated living, with spacious interiors and a peaceful setting.",image_url:"https://images.unsplash.com/photo-1600566753190-17f0baa2a6c3?auto=format&fit=crop&w=1200&q=85"}
  ];
  const tx=db.transaction(()=>demo.forEach(x=>insert.run(x)));
  tx();
}
seed();

app.use(express.json({limit:"1mb"}));
app.use(cookieParser());
app.use(express.urlencoded({extended:true}));

const publicLimiter=rateLimit({windowMs:60*1000,max:100,standardHeaders:true,legacyHeaders:false});
app.use("/api",publicLimiter);

function auth(req,res,next){
  const token=req.cookies.aura_admin;
  if(!token) return res.status(401).json({error:"Authentication required"});
  try{req.admin=jwt.verify(token,JWT_SECRET);next()}catch{return res.status(401).json({error:"Invalid session"})}
}
function makeToken(){return jwt.sign({role:"admin",email:ADMIN_EMAIL},JWT_SECRET,{expiresIn:"8h"});}
function uniqueSlug(name){
  const base=slugify(name,{lower:true,strict:true}) || crypto.randomUUID().slice(0,8);
  let slug=base, n=2;
  while(db.prepare("SELECT 1 FROM properties WHERE slug=?").get(slug)){slug=`${base}-${n++}`;}
  return slug;
}

const storage=multer.diskStorage({
  destination:(_,__,cb)=>cb(null,UPLOAD_DIR),
  filename:(_,file,cb)=>{
    const ext=path.extname(file.originalname).toLowerCase();
    cb(null,crypto.randomUUID()+ext);
  }
});
const upload=multer({
  storage,
  limits:{fileSize:5*1024*1024},
  fileFilter:(_,file,cb)=>cb(null,/^image\/(jpeg|png|webp)$/.test(file.mimetype))
});

app.post("/api/auth/login", async (req,res)=>{
  const {email,password}=req.body||{};
  if(email!==ADMIN_EMAIL) return res.status(401).json({error:"Invalid credentials"});
  const ok=await bcrypt.compare(String(password||""),await bcrypt.hash(ADMIN_PASSWORD,10));
  // Constant-time password check against the configured password.
  if(!ok) return res.status(401).json({error:"Invalid credentials"});
  res.cookie("aura_admin",makeToken(),{httpOnly:true,sameSite:"lax",secure:process.env.NODE_ENV==="production",maxAge:8*60*60*1000});
  res.json({ok:true});
});
app.get("/api/auth/me",auth,(req,res)=>res.json({email:req.admin.email}));
app.post("/api/auth/logout",(req,res)=>{res.clearCookie("aura_admin");res.json({ok:true});});

function publicProperty(row){
  return {...row, views:db.prepare("SELECT COUNT(*) c FROM page_views WHERE property_id=?").get(row.id).c};
}
app.get("/api/properties",(req,res)=>{
  res.json(db.prepare("SELECT * FROM properties ORDER BY created_at DESC").all().map(publicProperty));
});
app.get("/api/properties/all",auth,(req,res)=>{
  res.json(db.prepare("SELECT * FROM properties ORDER BY created_at DESC").all().map(publicProperty));
});
app.get("/api/properties/:slug",(req,res)=>{
  const row=db.prepare("SELECT * FROM properties WHERE slug=?").get(req.params.slug);
  if(!row) return res.status(404).json({error:"Property not found"});
  res.json(publicProperty(row));
});
app.post("/api/properties",auth,upload.single("image"),(req,res)=>{
  try{
    const b=req.body||{};
    if(!b.name||!b.type||!b.price||!b.beds||!b.baths||!b.area||!b.description||!b.overview||!req.file)
      return res.status(400).json({error:"All property fields and an image are required"});
    const imageUrl="/uploads/"+req.file.filename;
    const info=db.prepare(`INSERT INTO properties
      (slug,name,type,price,beds,baths,area,description,overview,image_url)
      VALUES (?,?,?,?,?,?,?,?,?,?)`).run(
        uniqueSlug(b.name),b.name,b.type,b.price,Number(b.beds),Number(b.baths),b.area,b.description,b.overview,imageUrl
      );
    res.status(201).json(db.prepare("SELECT * FROM properties WHERE id=?").get(info.lastInsertRowid));
  }catch(e){ if(req.file) fs.rmSync(path.join(UPLOAD_DIR,req.file.filename),{force:true}); res.status(500).json({error:"Could not create property"});}
});
app.delete("/api/properties/:id",auth,(req,res)=>{
  const row=db.prepare("SELECT * FROM properties WHERE id=?").get(Number(req.params.id));
  if(!row) return res.status(404).json({error:"Property not found"});
  db.prepare("DELETE FROM properties WHERE id=?").run(row.id);
  if(row.image_url?.startsWith("/uploads/")) fs.rmSync(path.join(UPLOAD_DIR,path.basename(row.image_url)),{force:true});
  res.json({ok:true});
});

app.post("/api/leads", (req,res)=>{
  const {name,email,phone,message,propertySlug}=req.body||{};
  if(!name||!email||!message) return res.status(400).json({error:"Name, email and message are required"});
  if(!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) return res.status(400).json({error:"Enter a valid email"});
  const property=propertySlug?db.prepare("SELECT id FROM properties WHERE slug=?").get(propertySlug):null;
  db.prepare("INSERT INTO leads(name,email,phone,message,property_id) VALUES (?,?,?,?,?)")
    .run(String(name).slice(0,100),String(email).slice(0,200),String(phone||"").slice(0,40),String(message).slice(0,4000),property?.id||null);
  res.status(201).json({ok:true});
});
app.get("/api/leads",auth,(req,res)=>{
  res.json(db.prepare(`SELECT leads.*, properties.name property_name
    FROM leads LEFT JOIN properties ON properties.id=leads.property_id
    ORDER BY leads.created_at DESC`).all());
});

app.post("/api/analytics/page-view",(req,res)=>{
  const page=String(req.body?.page||"/").slice(0,300);
  const slug=req.body?.propertyId;
  const property=slug?db.prepare("SELECT id FROM properties WHERE slug=?").get(slug):null;
  db.prepare("INSERT INTO page_views(page,property_id) VALUES (?,?)").run(page,property?.id||null);
  res.status(204).end();
});
app.get("/api/analytics",auth,(req,res)=>{
  const pages=db.prepare("SELECT page,COUNT(*) views FROM page_views GROUP BY page ORDER BY views DESC").all();
  res.json({pages});
});
app.get("/api/analytics/summary",auth,(req,res)=>{
  const properties=db.prepare("SELECT COUNT(*) c FROM properties").get().c;
  const leads=db.prepare("SELECT COUNT(*) c FROM leads").get().c;
  const pageViews=db.prepare("SELECT COUNT(*) c FROM page_views").get().c;
  const propertyViews=db.prepare("SELECT COUNT(*) c FROM page_views WHERE property_id IS NOT NULL").get().c;
  res.json({properties,leads,pageViews,propertyViews});
});

app.use("/uploads",express.static(UPLOAD_DIR));
app.use(express.static(ROOT));

app.get("*",(req,res)=>{
  if(req.path.startsWith("/api/")) return res.status(404).json({error:"Not found"});
  res.sendFile(path.join(ROOT,"index.html"));
});

app.listen(PORT,()=>console.log(`AURA ESTATES running on http://localhost:${PORT}`));
