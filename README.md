🦂 SAVAGE TECH

SCORPION PROTOCOL // PREMIUM FILE DATABASE

Savage Tech is a red-and-black cyber-themed platform for browsing, searching, and downloading authorized VPN/configuration files and public network-host records.

---

⚡ FEATURES

- 🦂 Scorpion Protocol UI
- 🔐 Protected administrator panel
- 📁 VPN/config file management
- 🔎 File and authorized-host search
- 🌍 Country and network filtering
- 📥 Secure file downloads
- 📊 Download statistics
- 📢 Updates and announcements
- 🔔 Notifications
- 🚨 Problem/report system
- 👤 User profiles
- 🛡️ Rate limiting
- 🔒 Secure admin sessions
- 📝 Administrative activity logs
- 📱 Mobile-responsive interface
- 🎬 Cinematic animated landing page

---

📂 PROJECT STRUCTURE

savage-tech/
│
├── public/
│   ├── index.html
│   ├── Main.html
│   ├── Support.html
│   ├── Search.html
│   ├── updates.html
│   ├── admin.html
│   └── Profile.html
│
├── data/
│   ├── vpn-files.json
│   ├── users.json
│   ├── updates.json
│   ├── notifications.json
│   ├── reports.json
│   ├── hosts.json
│   ├── settings.json
│   └── activity-logs.json
│
├── uploads/
│   └── vpn/
│
├── Server.js
├── package.json
├── vercel.json
├── Render.yaml
├── .env
├── .gitignore
└── README.md

---

🛠️ REQUIREMENTS

- Node.js 20+
- npm
- Git
- A server capable of running Node.js

---

🚀 INSTALLATION

Clone or download the project:

git clone YOUR_REPOSITORY_URL
cd savage-tech

Install dependencies:

npm install

Create your environment file:

cp .env.example .env

Configure the required environment variables in ".env".

Start Savage Tech:

npm start

For development:

npm run dev

The local server runs on:

http://localhost:3000

---

🔐 ENVIRONMENT VARIABLES

Example configuration:

PORT=3000
NODE_ENV=production

ADMIN_PASSWORD=YOUR_ADMIN_PASSWORD

ADMIN_SESSION_TTL=7200000
MAX_UPLOAD_SIZE=10485760

TRUST_PROXY=true

Never commit ".env" to a public repository.

---

👑 ADMIN SYSTEM

The administrator can manage the platform through:

/admin.html

Admin functionality includes:

- Upload files
- Delete files
- Manage authorized hosts
- Publish updates
- Publish notifications
- Review reports
- Manage platform settings
- View statistics
- View activity logs
- Monitor system status

Admin authentication is handled server-side by "Server.js".

The administrator password should remain in an environment variable and should never be placed in public frontend JavaScript.

---

📡 API

Public

GET  /api/health
GET  /api/files
GET  /api/search
GET  /api/stats
GET  /api/profile
GET  /api/updates
GET  /api/notifications
GET  /api/hosts
GET  /api/connection
GET  /api/session
GET  /api/files/:id/download
POST /api/reports

Administrator

POST   /api/admin/login
POST   /api/admin/logout
GET    /api/admin/session

GET    /api/admin/overview
GET    /api/admin/files
DELETE /api/admin/files/:id

POST   /api/files/upload

POST   /api/updates
DELETE /api/admin/updates/:id

POST   /api/notifications

GET    /api/admin/reports
PATCH  /api/admin/reports/:id

POST   /api/admin/hosts
DELETE /api/admin/hosts/:id

GET    /api/admin/users
GET    /api/admin/settings
POST   /api/admin/settings
GET    /api/admin/logs

Administrator endpoints require an authenticated admin session.

---

📥 FILE UPLOADS

Supported configuration formats include:

.ovpn
.ehi
.hat
.vpn
.conf
.txt

Maximum upload size is controlled by:

MAX_UPLOAD_SIZE=10485760

That default is 10 MB.

Only upload files that you are authorized to distribute.

Do not upload:

- stolen credentials
- private account information
- confidential infrastructure
- malware
- unauthorized private network data

---

🌐 AUTHORIZED HOST DATABASE

Savage Tech can display public or authorized network-host records.

Hosts should only be added when their publication and use are authorized.

The platform is not intended to facilitate unauthorized access to private systems or networks.

---

🛡️ SECURITY

Savage Tech includes several server-side protections:

- HTTP security headers
- Admin authentication
- HTTP-only admin session cookies
- SameSite cookie protection
- Login rate limiting
- API rate limiting
- Constant-time password comparison
- File-extension allowlisting
- Upload size restrictions
- Safe upload filenames
- Protected file paths
- Administrative audit logs
- Same-origin request checks
- Secure download handling

Security should always be configured for the actual deployment environment.

---

☁️ DEPLOYMENT

Render

The project includes:

Render.yaml

Render should use:

Build Command:
npm install

Start Command:
npm start

Set sensitive environment variables through the Render dashboard rather than committing them to Git.

Vercel

The project also includes:

vercel.json

The Express server is configured as the Vercel server entry point.

Important: the current server uses local JSON files and local uploads. Serverless deployments such as Vercel are not ideal for persistent file storage. For production use, move persistent data/uploads to a database and object-storage service.

---

💾 DATA STORAGE

During development, Savage Tech stores data in JSON files:

data/

Uploaded files are stored in:

uploads/vpn/

For a serious production deployment, use persistent external storage/database infrastructure rather than relying on an ephemeral filesystem.

---

📱 SUPPORT

Savage Tech support:

WhatsApp Support Group

https://chat.whatsapp.com/JYMTfZdxK0I2cHifou6EAp?s=cl&p=a&mlu=0&ilr=4

Direct Support

+44 7429 012 909

---

🦂 BRAND

SAVAGE TECH
SCORPION PROTOCOL

PRECISION IS POWER.
PATIENCE IS CONTROL.
STRIKE ONLY WHEN THE MOMENT IS YOURS.

---

📜 DISCLAIMER

Savage Tech is intended for legitimate distribution and management of authorized configuration files and public network information.

Users are responsible for ensuring that anything they upload, download, publish, or use complies with applicable laws, network policies, licensing terms, and authorization requirements.

---

🔧 DEVELOPMENT

Start development mode:

npm run dev

Start production mode:

npm start

Check server health:

GET /api/health

---

🏁 STATUS

╔══════════════════════════════════╗
║      SAVAGE TECH // ONLINE       ║
║                                  ║
║      SCORPION PROTOCOL           ║
║      FILE DATABASE READY         ║
║      ADMIN CORE READY            ║
║      SECURITY CORE ACTIVE        ║
╚══════════════════════════════════╝

Version: 1.0.0
Project: Savage Tech
Protocol: Scorpion Protocol
