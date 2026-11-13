# 🛡️ Zpluslink — Production Phishing Detector Backend

![OWASP ASVS Level 2](https://img.shields.io/badge/OWASP-ASVS%20Level%202%20Compliant-emerald?style=flat-square)
![Vercel Native](https://img.shields.io/badge/Deployment-Vercel%20Serverless-black?style=flat-square)
![Prisma + Neon](https://img.shields.io/badge/Database-Neon%20Serverless%20Postgres-blue?style=flat-square)

**Live Web Application:** [https://zplusec.vercel.app](https://zplusec.vercel.app)

---

## ⚡ One-Click Vercel Deploy

Deploy this complete backend & frontend pipeline directly to your Vercel project with one click:

[![Deploy with Vercel](https://vercel.com/button)](https://vercel.com/new/clone?repository-url=https%3A%2F%2Fgithub.com%2Fch-irax%2FZplus&env=DATABASE_URL,DIRECT_URL,JWT_SECRET,JWT_REFRESH_SECRET,UPSTASH_REDIS_REST_URL,UPSTASH_REDIS_REST_TOKEN&project-name=zpluslink)

### Vercel CLI Deployment Command
```bash
npx vercel --prod
```

---

## 🔐 OWASP Top 10 + ASVS Level 2 Security Specs

* **Strict SSRF Defense:** Automated IP-blocklist checking to block internal network scanning (`127.0.0.1`, `10.0.0.0/8`, `169.254.169.254`).
* **Rate Limiting:** Sliding-window 20 req/min rate limit via `@upstash/ratelimit` / serverless Edge memory store.
* **Input Sanitization:** Payload sanitization with DOMPurify & Zod boundary validation.
* **Anti-Clickjacking & Headers:** Strict Content Security Policy (CSP), HSTS, `X-Frame-Options: DENY`, `X-Content-Type-Options: nosniff`.
* **Session Security:** Dual-token JWT architecture with `httpOnly`, `Secure`, `SameSite=Strict` cookies.
* **Audit Trail:** Postgres-backed structured security event log (`AuditLog` table).

---

