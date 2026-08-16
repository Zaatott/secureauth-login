# SecureAuth — Full Login System

## Fitur
- Register & login
- Username/email login
- bcrypt password hashing
- SQLite database
- Session authentication
- Remember me
- Role user/admin
- Admin user management
- Change password
- Logout
- Login rate limiting
- Helmet security headers
- Responsive modern UI

## Menjalankan

Pastikan Node.js sudah terpasang.

```bash
npm install
npm start
```

Lalu buka:

http://localhost:3000


Untuk production, ubah kredensial melalui environment variable:

```bash
ADMIN_USERNAME=admin
ADMIN_EMAIL=admin@domain.com
## Admin production
SESSION_SECRET=random-secret-yang-panjang
NODE_ENV=production
```

## Struktur

- `server.js` — backend Express + API + database
- `public/` — frontend
- `data/users.db` — database otomatis dibuat
- `data/sessions.db` — session store otomatis dibuat

## Catatan production

Gunakan HTTPS, secret session yang panjang/random, password admin yang kuat, reverse proxy, backup database, dan environment variables. Jangan gunakan kredensial default di internet.
