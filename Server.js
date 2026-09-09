/*
╔══════════════════════════════════════════════════════════════╗
║                    🦂 SAVAGE TECH                           ║
║                    SERVER.JS // CORE                       ║
║                                                              ║
║  Central backend for the Savage Tech website                ║
║                                                              ║
║  Features                                                    ║
║  ├─ Admin authentication                                     ║
║  ├─ Session management                                       ║
║  ├─ File database                                            ║
║  ├─ Authorized file uploads                                  ║
║  ├─ Secure downloads                                         ║
║  ├─ Updates                                                  ║
║  ├─ Notifications                                            ║
║  ├─ Reports                                                  ║
║  ├─ Public hosts                                             ║
║  ├─ User/session statistics                                  ║
║  ├─ Admin activity logs                                      ║
║  ├─ System settings                                          ║
║  ├─ Rate limiting                                            ║
║  └─ Security headers                                         ║
╚══════════════════════════════════════════════════════════════╝
*/

require("dotenv").config();

const express = require("express");
const fs = require("fs");
const path = require("path");
const crypto = require("crypto");
const multer = require("multer");
const cookieParser = require("cookie-parser");

const app = express();

const PORT = Number(process.env.PORT || 3000);
const NODE_ENV = process.env.NODE_ENV || "development";

const ADMIN_PASSWORD =
  process.env.ADMIN_PASSWORD || "PIL922IAM839";

const SESSION_TTL =
  Number(process.env.ADMIN_SESSION_TTL || 2 * 60 * 60 * 1000);

const MAX_UPLOAD_SIZE =
  Number(process.env.MAX_UPLOAD_SIZE || 10 * 1024 * 1024);


/* ============================================================
   PATHS
============================================================ */

const ROOT = __dirname;

const PUBLIC_DIR =
  path.join(ROOT, "public");

const DATA_DIR =
  path.join(ROOT, "data");

const UPLOAD_DIR =
  path.join(ROOT, "uploads");

const VPN_DIR =
  path.join(UPLOAD_DIR, "vpn");


[
  DATA_DIR,
  UPLOAD_DIR,
  VPN_DIR
].forEach(dir => {

  if (!fs.existsSync(dir)) {
    fs.mkdirSync(dir, {
      recursive: true
    });
  }

});


/* ============================================================
   DATABASE FILES
============================================================ */

const DB = {

  files:
    path.join(DATA_DIR, "vpn-files.json"),

  users:
    path.join(DATA_DIR, "users.json"),

  updates:
    path.join(DATA_DIR, "updates.json"),

  notifications:
    path.join(DATA_DIR, "notifications.json"),

  reports:
    path.join(DATA_DIR, "reports.json"),

  hosts:
    path.join(DATA_DIR, "hosts.json"),

  settings:
    path.join(DATA_DIR, "settings.json"),

  logs:
    path.join(DATA_DIR, "activity-logs.json")

};


const DEFAULTS = {

  files: [],

  users: [],

  updates: [],

  notifications: [],

  reports: [],

  hosts: [],

  settings: {

    publicFileDatabase: true,

    downloadService: true,

    updatesChannel: true,

    maintenanceMode: false,

    registration: true

  },

  logs: []

};


function ensureDatabase(){

  Object.entries(DB).forEach(([key,file]) => {

    if (!fs.existsSync(file)) {

      writeJSON(
        file,
        DEFAULTS[key]
      );

    }

  });

}


ensureDatabase();


/* ============================================================
   JSON HELPERS
============================================================ */

function readJSON(file, fallback = []){

  try {

    const raw =
      fs.readFileSync(
        file,
        "utf8"
      );

    return JSON.parse(raw);

  } catch {

    return fallback;

  }

}


function writeJSON(file,data){

  const temporary =
    file + ".tmp";

  fs.writeFileSync(
    temporary,
    JSON.stringify(
      data,
      null,
      2
    ),
    "utf8"
  );

  fs.renameSync(
    temporary,
    file
  );

}


/* ============================================================
   SECURITY HELPERS
============================================================ */

function randomId(prefix = ""){

  return (
    prefix +
    crypto.randomBytes(16).toString("hex")
  );

}


function safeText(value,max = 500){

  return String(value ?? "")
    .replace(/[<>]/g,"")
    .trim()
    .slice(0,max);

}


function safeFileName(name){

  return path.basename(
    String(name || "")
      .replace(/[^a-zA-Z0-9._-]/g,"_")
  );

}


function hashValue(value){

  return crypto
    .createHash("sha256")
    .update(value)
    .digest("hex");

}


function constantTimeEqual(a,b){

  const A =
    Buffer.from(String(a));

  const B =
    Buffer.from(String(b));

  if(A.length !== B.length){

    return false;

  }

  return crypto.timingSafeEqual(
    A,
    B
  );

}


/* ============================================================
   ADMIN SESSIONS
============================================================ */

const sessions =
  new Map();


function createSession(){

  const token =
    crypto.randomBytes(48).toString("hex");

  sessions.set(
    token,
    {
      createdAt: Date.now(),
      expiresAt:
        Date.now() + SESSION_TTL
    }
  );

  return token;

}


function destroySession(token){

  if(token){

    sessions.delete(token);

  }

}


function getSession(req){

  const token =
    req.cookies?.savage_admin_session;

  if(!token){

    return null;

  }

  const session =
    sessions.get(token);

  if(!session){

    return null;

  }

  if(
    Date.now() >
    session.expiresAt
  ){

    sessions.delete(token);

    return null;

  }

  return {
    token,
    session
  };

}


/* ============================================================
   LOGIN RATE LIMIT
============================================================ */

const loginAttempts =
  new Map();


const LOGIN_WINDOW =
  10 * 60 * 1000;

const MAX_LOGIN_ATTEMPTS =
  8;


function getClientAddress(req){

  return (
    req.ip ||
    req.socket?.remoteAddress ||
    "unknown"
  );

}


function checkLoginRateLimit(req){

  const key =
    getClientAddress(req);

  const now =
    Date.now();

  let record =
    loginAttempts.get(key);

  if(!record){

    record = {
      count: 0,
      firstAttempt: now
    };

    loginAttempts.set(
      key,
      record
    );

  }

  if(
    now - record.firstAttempt >
    LOGIN_WINDOW
  ){

    record.count = 0;
    record.firstAttempt = now;

  }

  return record.count <
    MAX_LOGIN_ATTEMPTS;

}


function registerFailedLogin(req){

  const key =
    getClientAddress(req);

  const now =
    Date.now();

  let record =
    loginAttempts.get(key);

  if(!record){

    record = {
      count: 0,
      firstAttempt: now
    };

  }

  record.count++;

  loginAttempts.set(
    key,
    record
  );

}


/* ============================================================
   AUDIT LOGGING
============================================================ */

function audit(
  event,
  status = "SUCCESS",
  req = null,
  details = {}
){

  const logs =
    readJSON(
      DB.logs,
      []
    );

  logs.unshift({

    id:
      randomId("LOG-"),

    timestamp:
      new Date().toISOString(),

    event:
      safeText(event,200),

    actor:
      "ADMIN",

    status:
      safeText(status,50),

    ip:
      req
        ? getClientAddress(req)
        : "SYSTEM",

    details

  });

  writeJSON(
    DB.logs,
    logs.slice(0,1000)
  );

}


/* ============================================================
   SECURITY HEADERS
============================================================ */

app.disable("x-powered-by");

app.set(
  "trust proxy",
  process.env.TRUST_PROXY === "true"
);


app.use((req,res,next)=>{

  res.setHeader(
    "X-Content-Type-Options",
    "nosniff"
  );

  res.setHeader(
    "X-Frame-Options",
    "DENY"
  );

  res.setHeader(
    "Referrer-Policy",
    "strict-origin-when-cross-origin"
  );

  res.setHeader(
    "Permissions-Policy",
    "geolocation=(), microphone=(), camera=()"
  );

  if(NODE_ENV === "production"){

    res.setHeader(
      "Strict-Transport-Security",
      "max-age=31536000; includeSubDomains"
    );

  }

  next();

});


/* ============================================================
   REQUEST PARSERS
============================================================ */

app.use(
  express.json({
    limit:"100kb"
  })
);

app.use(
  express.urlencoded({
    extended:false,
    limit:"100kb"
  })
);

app.use(
  cookieParser()
);


/* ============================================================
   BASIC RATE LIMITER
============================================================ */

const requestBuckets =
  new Map();


function rateLimit(
  windowMs = 60_000,
  maxRequests = 100
){

  return (req,res,next)=>{

    const key =
      getClientAddress(req);

    const now =
      Date.now();

    let bucket =
      requestBuckets.get(key);

    if(!bucket){

      bucket = {
        start: now,
        count: 0
      };

      requestBuckets.set(
        key,
        bucket
      );

    }

    if(
      now - bucket.start >
      windowMs
    ){

      bucket.start = now;
      bucket.count = 0;

    }

    bucket.count++;

    if(
      bucket.count >
      maxRequests
    ){

      return res
        .status(429)
        .json({
          error:
            "Too many requests"
        });

    }

    next();

  };

}


app.use(
  rateLimit(
    60_000,
    180
  )
);


/* ============================================================
   ADMIN MIDDLEWARE
============================================================ */

function requireAdmin(req,res,next){

  const session =
    getSession(req);

  if(!session){

    return res
      .status(401)
      .json({
        error:
          "Admin authentication required"
      });

  }

  req.adminSession =
    session;

  next();

}


/* ============================================================
   CSRF-STYLE ORIGIN CHECK
============================================================ */

function checkOrigin(req,res,next){

  const origin =
    req.headers.origin;

  if(!origin){

    return next();

  }

  const host =
    req.headers.host;

  try{

    const originURL =
      new URL(origin);

    if(
      originURL.host !== host
    ){

      return res
        .status(403)
        .json({
          error:
            "Origin rejected"
        });

    }

  }catch{

    return res
      .status(403)
      .json({
        error:
          "Invalid origin"
      });

  }

  next();

}


/* ============================================================
   ADMIN LOGIN
============================================================ */

app.post(
  "/api/admin/login",
  rateLimit(
    10 * 60_000,
    20
  ),
  checkOrigin,
  (req,res)=>{

    if(
      !checkLoginRateLimit(req)
    ){

      audit(
        "Admin login rate limited",
        "BLOCKED",
        req
      );

      return res
        .status(429)
        .json({
          error:
            "Too many login attempts"
        });

    }

    const password =
      String(
        req.body?.password || ""
      );

    if(
      !password ||
      !constantTimeEqual(
        password,
        ADMIN_PASSWORD
      )
    ){

      registerFailedLogin(req);

      audit(
        "Admin login attempt",
        "FAILED",
        req
      );

      return res
        .status(401)
        .json({
          error:
            "Authentication failed"
        });

    }

    const token =
      createSession();

    res.cookie(
      "savage_admin_session",
      token,
      {
        httpOnly:true,

        secure:
          NODE_ENV === "production",

        sameSite:"strict",

        maxAge:
          SESSION_TTL,

        path:"/"
      }
    );

    audit(
      "Admin login",
      "SUCCESS",
      req
    );

    res.json({
      success:true,
      message:"Access granted"
    });

  }
);


/* ============================================================
   ADMIN LOGOUT
============================================================ */

app.post(
  "/api/admin/logout",
  requireAdmin,
  (req,res)=>{

    destroySession(
      req.adminSession.token
    );

    res.clearCookie(
      "savage_admin_session",
      {
        httpOnly:true,
        sameSite:"strict",
        secure:
          NODE_ENV === "production",
        path:"/"
      }
    );

    audit(
      "Admin logout",
      "SUCCESS",
      req
    );

    res.json({
      success:true
    });

  }
);


/* ============================================================
   SESSION STATUS
============================================================ */

app.get(
  "/api/admin/session",
  requireAdmin,
  (req,res)=>{

    res.json({
      authenticated:true,
      expiresAt:
        req.adminSession.session.expiresAt
    });

  }
);


/* ============================================================
   HEALTH
============================================================ */

app.get(
  "/api/health",
  (req,res)=>{

    res.json({

      status:"online",

      service:"Savage Tech",

      timestamp:
        new Date().toISOString(),

      uptime:
        Math.round(
          process.uptime()
        )

    });

  }
);


/* ============================================================
   PUBLIC FILE API
============================================================ */

app.get(
  "/api/files",
  (req,res)=>{

    const settings =
      readJSON(
        DB.settings,
        DEFAULTS.settings
      );

    if(
      settings.publicFileDatabase === false
    ){

      return res.json([]);

    }

    const files =
      readJSON(
        DB.files,
        []
      );

    const publicFiles =
      files.map(file=>({

        id:file.id,

        name:file.name,

        country:file.country,

        network:file.network,

        type:file.type,

        size:file.size,

        version:file.version,

        downloads:file.downloads || 0,

        description:file.description,

        createdAt:file.createdAt

      }));

    res.json(
      publicFiles
    );

  }
);


/* ============================================================
   SEARCH API
============================================================ */

app.get(
  "/api/search",
  (req,res)=>{

    const query =
      safeText(
        req.query.q,
        100
      ).toLowerCase();

    const country =
      safeText(
        req.query.country,
        50
      ).toLowerCase();

    const type =
      safeText(
        req.query.type,
        30
      ).toLowerCase();

    const network =
      safeText(
        req.query.network,
        50
      ).toLowerCase();

    const host =
      safeText(
        req.query.host,
        200
      ).toLowerCase();

    const files =
      readJSON(
        DB.files,
        []
      );

    const hosts =
      readJSON(
        DB.hosts,
        []
      );


    const fileResults =
      files.filter(file=>{

        const searchable = [

          file.name,
          file.country,
          file.network,
          file.type,
          file.description

        ]
        .join(" ")
        .toLowerCase();

        return (

          (!query ||
            searchable.includes(query)) &&

          (!country ||
            String(file.country)
              .toLowerCase()
              .includes(country)) &&

          (!type ||
            String(file.type)
              .toLowerCase()
              .includes(type)) &&

          (!network ||
            String(file.network)
              .toLowerCase()
              .includes(network))

        );

      });


    const hostResults =
      hosts.filter(item=>{

        if(
          item.status &&
          item.status !== "ACTIVE"
        ){

          return false;

        }

        const searchable = [

          item.host,
          item.country,
          item.network

        ]
        .join(" ")
        .toLowerCase();

        return (

          (!query ||
            searchable.includes(query)) &&

          (!host ||
            String(item.host)
              .toLowerCase()
              .includes(host))

        );

      });


    res.json({

      results:[
        ...fileResults.map(file=>({

          ...file,

          resultType:"file"

        })),

        ...hostResults.map(item=>({

          ...item,

          resultType:"host"

        }))

      ]

    });

  }
);


/* ============================================================
   FILE DOWNLOAD
============================================================ */

app.get(
  "/api/files/:id/download",
  rateLimit(
    60_000,
    30
  ),
  (req,res)=>{

    const settings =
      readJSON(
        DB.settings,
        DEFAULTS.settings
      );

    if(
      settings.downloadService === false
    ){

      return res
        .status(503)
        .json({
          error:
            "Download service disabled"
        });

    }

    const files =
      readJSON(
        DB.files,
        []
      );

    const file =
      files.find(
        item =>
          item.id === req.params.id
      );

    if(!file){

      return res
        .status(404)
        .json({
          error:"File not found"
        });

    }

    const fullPath =
      path.resolve(
        VPN_DIR,
        file.storageName
      );

    const uploadRoot =
      path.resolve(VPN_DIR);

    if(
      !fullPath.startsWith(
        uploadRoot + path.sep
      )
    ){

      return res
        .status(400)
        .json({
          error:"Invalid file path"
        });

    }

    if(
      !fs.existsSync(fullPath)
    ){

      return res
        .status(404)
        .json({
          error:
            "Stored file unavailable"
        });

    }

    file.downloads =
      Number(file.downloads || 0) + 1;

    writeJSON(
      DB.files,
      files
    );

    audit(
      "File downloaded",
      "SUCCESS",
      req,
      {
        fileId:file.id
      }
    );

    res.download(
      fullPath,
      safeFileName(
        file.originalName ||
        file.name ||
        "download"
      )
    );

  }
);


/* ============================================================
   UPLOAD STORAGE
============================================================ */

const storage =
  multer.diskStorage({

    destination:
      (req,file,cb)=>{

        cb(
          null,
          VPN_DIR
        );

      },

    filename:
      (req,file,cb)=>{

        const extension =
          path.extname(
            file.originalname
          ).toLowerCase();

        const generated =
          crypto
            .randomBytes(20)
            .toString("hex");

        cb(
          null,
          generated + extension
        );

      }

  });


const allowedExtensions =
  new Set([

    ".ovpn",
    ".ehi",
    ".hat",
    ".vpn",
    ".conf",
    ".txt"

  ]);


const upload =
  multer({

    storage,

    limits:{
      fileSize:
        MAX_UPLOAD_SIZE
    },

    fileFilter:
      (req,file,cb)=>{

        const extension =
          path.extname(
            file.originalname
          ).toLowerCase();

        if(
          !allowedExtensions.has(
            extension
          )
        ){

          return cb(
            new Error(
              "File type not allowed"
            )
          );

        }

        cb(
          null,
          true
        );

      }

  });


/* ============================================================
   ADMIN FILE UPLOAD
============================================================ */

app.post(
  "/api/files/upload",
  requireAdmin,
  checkOrigin,
  upload.single("file"),
  (req,res)=>{

    try{

      if(!req.file){

        return res
          .status(400)
          .json({
            error:
              "No file uploaded"
          });

      }

      const files =
        readJSON(
          DB.files,
          []
        );

      const file = {

        id:
          randomId("FILE-"),

        name:
          safeText(
            req.body.name ||
            req.file.originalname,
            150
          ),

        country:
          safeText(
            req.body.country,
            80
          ),

        network:
          safeText(
            req.body.network,
            80
          ),

        type:
          safeText(
            req.body.type ||
            path.extname(
              req.file.originalname
            ),
            30
          ),

        description:
          safeText(
            req.body.description,
            1000
          ),

        version:
          safeText(
            req.body.version ||
            "1.0",
            30
          ),

        size:
          req.file.size,

        originalName:
          safeFileName(
            req.file.originalname
          ),

        storageName:
          req.file.filename,

        downloads:0,

        createdAt:
          new Date().toISOString(),

        updatedAt:
          new Date().toISOString(),

        status:
          "PUBLISHED"

      };


      files.unshift(file);

      writeJSON(
        DB.files,
        files
      );


      audit(
        "File uploaded",
        "SUCCESS",
        req,
        {
          fileId:file.id,
          name:file.name
        }
      );


      res.status(201).json({

        success:true,

        file:{
          id:file.id,
          name:file.name,
          country:file.country,
          network:file.network,
          type:file.type,
          size:file.size
        }

      });

    }catch(error){

      if(req.file){

        try{

          fs.unlinkSync(
            path.join(
              VPN_DIR,
              req.file.filename
            )
          );

        }catch{}

      }

      console.error(
        "Upload error:",
        error
      );

      res
        .status(500)
        .json({
          error:
            "Upload failed"
        });

    }

  }
);


/* ============================================================
   DELETE FILE
============================================================ */

app.delete(
  "/api/admin/files/:id",
  requireAdmin,
  checkOrigin,
  (req,res)=>{

    const files =
      readJSON(
        DB.files,
        []
      );

    const index =
      files.findIndex(
        item =>
          item.id === req.params.id
      );

    if(index === -1){

      return res
        .status(404)
        .json({
          error:
            "File not found"
        });

    }

    const file =
      files[index];

    const storagePath =
      path.resolve(
        VPN_DIR,
        file.storageName
      );

    const root =
      path.resolve(
        VPN_DIR
      );

    if(
      storagePath.startsWith(
        root + path.sep
      ) &&
      fs.existsSync(storagePath)
    ){

      fs.unlinkSync(
        storagePath
      );

    }

    files.splice(
      index,
      1
    );

    writeJSON(
      DB.files,
      files
    );

    audit(
      "File deleted",
      "SUCCESS",
      req,
      {
        fileId:file.id
      }
    );

    res.json({
      success:true
    });

  }
);


/* ============================================================
   STATS
============================================================ */

app.get(
  "/api/stats",
  (req,res)=>{

    const files =
      readJSON(
        DB.files,
        []
      );

    const users =
      readJSON(
        DB.users,
        []
      );

    const reports =
      readJSON(
        DB.reports,
        []
      );


    const countries =
      new Set(
        files
          .map(file=>file.country)
          .filter(Boolean)
      );


    const downloads =
      files.reduce(
        (sum,file)=>
          sum +
          Number(
            file.downloads || 0
          ),
        0
      );


    res.json({

      files:
        files.length,

      downloads,

      countries:
        countries.size,

      users:
        users.length,

      reports:
        reports.filter(
          report =>
            report.status !==
            "RESOLVED"
        ).length

    });

  }
);


/* ============================================================
   PROFILE
============================================================ */

app.get(
  "/api/profile",
  (req,res)=>{

    res.json({

      profile:{

        name:
          "SAVAGE USER",

        tag:
          "SCORPION OPERATIVE",

        bio:
          "Connected to the Savage Tech file distribution core.",

        downloads:0,

        saved:0,

        countries:0,

        activity:"LOW"

      }

    });

  }
);


/* ============================================================
   UPDATES
============================================================ */

app.get(
  "/api/updates",
  (req,res)=>{

    const settings =
      readJSON(
        DB.settings,
        DEFAULTS.settings
      );

    if(
      settings.updatesChannel === false
    ){

      return res.json([]);

    }

    const updates =
      readJSON(
        DB.updates,
        []
      );

    res.json(
      updates
    );

  }
);


/* ============================================================
   ADMIN CREATE UPDATE
============================================================ */

app.post(
  "/api/updates",
  requireAdmin,
  checkOrigin,
  (req,res)=>{

    const title =
      safeText(
        req.body.title,
        150
      );

    const message =
      safeText(
        req.body.message,
        3000
      );

    const category =
      safeText(
        req.body.category ||
        "SYSTEM",
        40
      );

    if(
      !title ||
      !message
    ){

      return res
        .status(400)
        .json({
          error:
            "Title and message required"
        });

    }

    const updates =
      readJSON(
        DB.updates,
        []
      );

    const update={

      id:
        randomId("UPD-"),

      title,

      message,

      category,

      createdAt:
        new Date().toISOString(),

      pinned:
        Boolean(
          req.body.pinned
        )

    };

    updates.unshift(
      update
    );

    writeJSON(
      DB.updates,
      updates
    );

    audit(
      "Update published",
      "SUCCESS",
      req,
      {
        updateId:update.id
      }
    );

    res.status(201).json({

      success:true,

      update

    });

  }
);


/* ============================================================
   ADMIN DELETE UPDATE
============================================================ */

app.delete(
  "/api/admin/updates/:id",
  requireAdmin,
  checkOrigin,
  (req,res)=>{

    const updates =
      readJSON(
        DB.updates,
        []
      );

    const filtered =
      updates.filter(
        item =>
          item.id !== req.params.id
      );

    if(
      filtered.length ===
      updates.length
    ){

      return res
        .status(404)
        .json({
          error:
            "Update not found"
        });

    }

    writeJSON(
      DB.updates,
      filtered
    );

    audit(
      "Update deleted",
      "SUCCESS",
      req,
      {
        updateId:req.params.id
      }
    );

    res.json({
      success:true
    });

  }
);


/* ============================================================
   NOTIFICATIONS
============================================================ */

app.get(
  "/api/notifications",
  (req,res)=>{

    const notifications =
      readJSON(
        DB.notifications,
        []
      );

    res.json(
      notifications
    );

  }
);


app.post(
  "/api/notifications",
  requireAdmin,
  checkOrigin,
  (req,res)=>{

    const title =
      safeText(
        req.body.title,
        150
      );

    const message =
      safeText(
        req.body.message,
        2000
      );

    const priority =
      safeText(
        req.body.priority ||
        "NORMAL",
        30
      );

    if(
      !title ||
      !message
    ){

      return res
        .status(400)
        .json({
          error:
            "Title and message required"
        });

    }

    const notifications =
      readJSON(
        DB.notifications,
        []
      );

    const notification={

      id:
        randomId("NOTIF-"),

      title,

      message,

      priority,

      createdAt:
        new Date().toISOString(),

      read:false

    };

    notifications.unshift(
      notification
    );

    writeJSON(
      DB.notifications,
      notifications
    );

    audit(
      "Notification created",
      "SUCCESS",
      req,
      {
        notificationId:
          notification.id
      }
    );

    res.status(201).json({

      success:true,

      notification

    });

  }
);


/* ============================================================
   REPORTS
============================================================ */

app.post(
  "/api/reports",
  rateLimit(
    60_000,
    15
  ),
  (req,res)=>{

    const reports =
      readJSON(
        DB.reports,
        []
      );

    const report={

      id:
        randomId("REP-"),

      fileName:
        safeText(
          req.body.fileName,
          150
        ),

      type:
        safeText(
          req.body.type,
          100
        ),

      description:
        safeText(
          req.body.description,
          3000
        ),

      createdAt:
        new Date().toISOString(),

      status:
        "PENDING"

    };

    if(
      !report.type ||
      !report.description
    ){

      return res
        .status(400)
        .json({
          error:
            "Report type and description required"
        });

    }

    reports.unshift(
      report
    );

    writeJSON(
      DB.reports,
      reports
    );

    audit(
      "Support report submitted",
      "SUCCESS",
      req,
      {
        reportId:report.id
      }
    );

    res.status(201).json({

      success:true,

      reportId:
        report.id

    });

  }
);


/* ============================================================
   ADMIN REPORTS
============================================================ */

app.get(
  "/api/admin/reports",
  requireAdmin,
  (req,res)=>{

    res.json(
      readJSON(
        DB.reports,
        []
      )
    );

  }
);


/* ============================================================
   RESOLVE REPORT
============================================================ */

app.patch(
  "/api/admin/reports/:id",
  requireAdmin,
  checkOrigin,
  (req,res)=>{

    const reports =
      readJSON(
        DB.reports,
        []
      );

    const report =
      reports.find(
        item =>
          item.id === req.params.id
      );

    if(!report){

      return res
        .status(404)
        .json({
          error:
            "Report not found"
        });

    }

    report.status =
      safeText(
        req.body.status ||
        "RESOLVED",
        30
      );

    report.updatedAt =
      new Date().toISOString();

    writeJSON(
      DB.reports,
      reports
    );

    audit(
      "Support report updated",
      "SUCCESS",
      req,
      {
        reportId:
          report.id
      }
    );

    res.json({

      success:true,

      report

    });

  }
);


/* ============================================================
   PUBLIC HOSTS
============================================================ */

app.get(
  "/api/hosts",
  (req,res)=>{

    const hosts =
      readJSON(
        DB.hosts,
        []
      );

    res.json(
      hosts.filter(
        host =>
          host.status ===
          "ACTIVE"
      )
    );

  }
);


/* ============================================================
   ADMIN HOST CREATION
============================================================ */

app.post(
  "/api/admin/hosts",
  requireAdmin,
  checkOrigin,
  (req,res)=>{

    const host =
      safeText(
        req.body.host,
        255
      );

    const network =
      safeText(
        req.body.network,
        100
      );

    const country =
      safeText(
        req.body.country,
        100
      );

    const status =
      safeText(
        req.body.status ||
        "ACTIVE",
        30
      );

    if(!host){

      return res
        .status(400)
        .json({
          error:
            "Host required"
        });

    }

    /*
      Only publish hosts that you are
      authorized to list.
    */

    const hosts =
      readJSON(
        DB.hosts,
        []
      );

    const record={

      id:
        randomId("HOST-"),

      host,

      network,

      country,

      status,

      createdAt:
        new Date().toISOString()

    };

    hosts.unshift(
      record
    );

    writeJSON(
      DB.hosts,
      hosts
    );

    audit(
      "Public host added",
      "SUCCESS",
      req,
      {
        hostId:record.id
      }
    );

    res.status(201).json({

      success:true,

      host:record

    });

  }
);


/* ============================================================
   DELETE PUBLIC HOST
============================================================ */

app.delete(
  "/api/admin/hosts/:id",
  requireAdmin,
  checkOrigin,
  (req,res)=>{

    const hosts =
      readJSON(
        DB.hosts,
        []
      );

    const filtered =
      hosts.filter(
        host =>
          host.id !==
          req.params.id
      );

    if(
      filtered.length ===
      hosts.length
    ){

      return res
        .status(404)
        .json({
          error:
            "Host not found"
        });

    }

    writeJSON(
      DB.hosts,
      filtered
    );

    audit(
      "Public host deleted",
      "SUCCESS",
      req,
      {
        hostId:req.params.id
      }
    );

    res.json({
      success:true
    });

  }
);


/* ============================================================
   USERS
============================================================ */

app.get(
  "/api/admin/users",
  requireAdmin,
  (req,res)=>{

    const users =
      readJSON(
        DB.users,
        []
      );

    /*
      Do not expose sensitive authentication
      information through this endpoint.
    */

    res.json(
      users.map(user=>({

        id:user.id,

        username:
          user.username || "USER",

        device:
          user.device || "Unknown",

        status:
          user.status || "ACTIVE",

        lastActive:
          user.lastActive || null

      }))
    );

  }
);


/* ============================================================
   USER REGISTRATION / SESSION RECORD
============================================================ */

app.post(
  "/api/session",
  rateLimit(
    60_000,
    20
  ),
  (req,res)=>{

    const settings =
      readJSON(
        DB.settings,
        DEFAULTS.settings
      );

    if(
      settings.registration === false
    ){

      return res
        .status(403)
        .json({
          error:
            "Registration disabled"
        });

    }

    const users =
      readJSON(
        DB.users,
        []
      );

    const user={

      id:
        randomId("USER-"),

      username:
        safeText(
          req.body.username ||
          "SAVAGE USER",
          80
        ),

      device:
        safeText(
          req.body.device ||
          "Unknown",
          50
        ),

      status:
        "ACTIVE",

      lastActive:
        new Date().toISOString(),

      createdAt:
        new Date().toISOString()

    };

    users.unshift(
      user
    );

    writeJSON(
      DB.users,
      users
    );

    res.status(201).json({

      success:true,

      userId:
        user.id

    });

  }
);


/* ============================================================
   ADMIN SETTINGS
============================================================ */

app.get(
  "/api/admin/settings",
  requireAdmin,
  (req,res)=>{

    res.json(
      readJSON(
        DB.settings,
        DEFAULTS.settings
      )
    );

  }
);


app.post(
  "/api/admin/settings",
  requireAdmin,
  checkOrigin,
  (req,res)=>{

    const settings =
      readJSON(
        DB.settings,
        DEFAULTS.settings
      );

    const allowed = [

      "publicFileDatabase",
      "downloadService",
      "updatesChannel",
      "maintenanceMode",
      "registration"

    ];

    allowed.forEach(key=>{

      if(
        typeof req.body[key] ===
        "boolean"
      ){

        settings[key] =
          req.body[key];

      }

    });

    writeJSON(
      DB.settings,
      settings
    );

    audit(
      "System settings changed",
      "SUCCESS",
      req
    );

    res.json({

      success:true,

      settings

    });

  }
);


/* ============================================================
   ADMIN LOGS
============================================================ */

app.get(
  "/api/admin/logs",
  requireAdmin,
  (req,res)=>{

    const logs =
      readJSON(
        DB.logs,
        []
      );

    res.json({

      logs:
        logs.slice(0,100)

    });

  }
);


/* ============================================================
   ADMIN OVERVIEW
============================================================ */

app.get(
  "/api/admin/overview",
  requireAdmin,
  (req,res)=>{

    const files =
      readJSON(
        DB.files,
        []
      );

    const users =
      readJSON(
        DB.users,
        []
      );

    const reports =
      readJSON(
        DB.reports,
        []
      );

    const updates =
      readJSON(
        DB.updates,
        []
      );

    const notifications =
      readJSON(
        DB.notifications,
        []
      );

    const hosts =
      readJSON(
        DB.hosts,
        []
      );

    const downloads =
      files.reduce(
        (total,file)=>
          total +
          Number(
            file.downloads || 0
          ),
        0
      );

    res.json({

      files:
        files.length,

      downloads,

      users:
        users.length,

      hosts:
        hosts.length,

      countries:
        new Set(
          files
            .map(
              file =>
                file.country
            )
            .filter(Boolean)
        ).size,

      pendingReports:
        reports.filter(
          report =>
            report.status !==
            "RESOLVED"
        ).length,

      updates:
        updates.length,

      notifications:
        notifications.length

    });

  }
);


/* ============================================================
   ADMIN FILE LIST
============================================================ */

app.get(
  "/api/admin/files",
  requireAdmin,
  (req,res)=>{

    const files =
      readJSON(
        DB.files,
        []
      );

    res.json(
      files
    );

  }
);


/* ============================================================
   ERROR HANDLER
============================================================ */

app.use(
  (error,req,res,next)=>{

    console.error(
      "[SERVER ERROR]",
      error
    );

    if(
      error.code ===
      "LIMIT_FILE_SIZE"
    ){

      return res
        .status(413)
        .json({
          error:
            "File exceeds upload size limit"
        });

    }

    if(
      error.message ===
      "File type not allowed"
    ){

      return res
        .status(400)
        .json({
          error:
            "File type not allowed"
        });

    }

    res
      .status(500)
      .json({
        error:
          "Internal server error"
      });

  }
);


/* ============================================================
   STATIC WEBSITE
============================================================ */

if(
  fs.existsSync(
    PUBLIC_DIR
  )
){

  app.use(
    express.static(
      PUBLIC_DIR,
      {
        index:"index.html",

        dotfiles:"deny",

        extensions:[
          "html"
        ]

      }
    )
  );

}


/* ============================================================
   404
============================================================ */

app.use(
  (req,res)=>{

    if(
      req.path.startsWith("/api/")
    ){

      return res
        .status(404)
        .json({
          error:
            "API endpoint not found"
        });

    }

    res
      .status(404)
      .send("404 — Savage Tech resource not found");

  }
);


/* ============================================================
   START
============================================================ */

const server =
  app.listen(
    PORT,
    "0.0.0.0",
    ()=>{
      console.log("");
      console.log(
        "╔════════════════════════════════════════════╗"
      );
      console.log(
        "║       🦂 SAVAGE TECH SERVER ONLINE        ║"
      );
      console.log(
        "╠════════════════════════════════════════════╣"
      );
      console.log(
        `║ PORT: ${PORT}`
      );
      console.log(
        `║ MODE: ${NODE_ENV}`
      );
      console.log(
        "║ CORE: SCORPION PROTOCOL"
      );
      console.log(
        "║ API:  ONLINE"
      );
      console.log(
        "╚════════════════════════════════════════════╝"
      );
      console.log("");
    }
  );


/* ============================================================
   GRACEFUL SHUTDOWN
============================================================ */

function shutdown(signal){

  console.log(
    `\n${signal} received. Shutting down...`
  );

  server.close(()=>{
    console.log(
      "Savage Tech server stopped."
    );

    process.exit(0);
  });

}


process.on(
  "SIGTERM",
  ()=>shutdown("SIGTERM")
);

process.on(
  "SIGINT",
  ()=>shutdown("SIGINT")
);


/* ============================================================
   SESSION CLEANUP
============================================================ */

setInterval(()=>{

  const now =
    Date.now();

  for(
    const [token,session]
    of sessions
  ){

    if(
      now >
      session.expiresAt
    ){

      sessions.delete(
        token
      );

    }

  }

},15 * 60 * 1000);


/* ============================================================
   LOGIN BUCKET CLEANUP
============================================================ */

setInterval(()=>{

  const now =
    Date.now();

  for(
    const [key,record]
    of loginAttempts
  ){

    if(
      now - record.firstAttempt >
      LOGIN_WINDOW
    ){

      loginAttempts.delete(
        key
      );

    }

  }

},10 * 60 * 1000);
