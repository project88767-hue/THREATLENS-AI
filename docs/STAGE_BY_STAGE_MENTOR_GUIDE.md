# THREATLENS AI — Complete Beginner-Friendly Mentor Guide (English + Hinglish)

Welcome! Yeh guide aapko **THREATLENS AI** ke har ek stage, technology choice, code structure, run commands, testing, aur troubleshooting ko step-by-step simple English + Hinglish mein samjhayegi — taaki aap interviews, viva, ya portfolio walkthrough mein har line confidently explain kar sako.

---

## Stage 1: Architecture & Technology Decisions (Kyun use kiya har tool?)

1. **Frontend (`frontend/` — React + TypeScript + Tailwind CSS + Recharts + Lucide)**:
   - **Why?** SOC analysts ko ek fast, dark-themed dashboard chahiye hota hai jahan charts (Recharts), risk gauges, aur threat graphs bina page reload ke update ho sakein. TypeScript compile-time par bugs pakad leta hai.
2. **Backend API (`backend/` — Node.js + Express + TypeScript + Prisma + Zod)**:
   - **Why?** Express REST API authentication (JWT + Cookies), Role-Based Access Control (`ADMIN`, `ANALYST`, `VIEWER`), rate limiting, CSRF check, aur Audit Logging handle karta hai. **Frontend kabhi bhi external API keys nahi dekhta** — saare requests secure backend ke through jaate hain!
3. **Cybersecurity Analysis Engine (`analysis-engine/` — Python + FastAPI)**:
   - **Why?** Cybersecurity aur AI ecosystem mein Python sabse strong hai (`email` RFC header parsing, `ipaddress` SSRF filtering, async `httpx` intelligence adapters, Shannon entropy calculation, aur LLM integration). FastAPI ultra-fast async APIs aur automatic Pydantic validation deta hai.
4. **Database (`PostgreSQL` + `Prisma ORM`)**:
   - **Why?** Investigations, Indicators, ScanResults, Evidence, Incidents, Reports, aur AuditLogs ke beech strong relational links (`Foreign Keys`) hote hain. Prisma SQL Injection prevent karta hai aur type-safe queries deta hai.
5. **Mobile (`mobile/` — React Native + Expo)**:
   - **Why?** Same Express REST APIs (`/api/auth/login`, `/api/scans/*`, `/api/incidents`) reuse karke Android SOC app bina backend rewrite kiye kaam karta hai!

---

## Stage 2: Security Controls (OWASP Top 10 Kaise Implement Hua?)

- **SSRF Protection (`analysis-engine/app/security/ssrf.py` & `backend/src/lib/engineClient.ts`)**:
  - Agar koi user `http://127.0.0.1`, `http://localhost`, `http://192.168.1.1`, ya cloud metadata IP `http://169.254.169.254` scan karne ki koshish kare, toh system turant `HTTP 403 SSRF Protection` return karke block kar deta hai.
- **Password Hashing (`backend/src/routes/auth.routes.ts`)**:
  - Passwords kabhi plain text mein save nahi hote — `bcryptjs` cost factor `12` ke saath hash hote hain.
- **RBAC (`backend/src/middleware/auth.ts`)**:
  - `VIEWER` sirf reports aur dashboards dekh sakta hai (`POST /api/scans/*` par `403 Forbidden` aayega).
  - `ANALYST` scans run kar sakta hai, investigations aur incidents manage kar sakta hai.
  - `ADMIN` users ke roles update kar sakta hai aur `/admin` mein **Audit Logs** dekh sakta hai.
- **Graceful Provider Fallbacks (`analysis-engine/app/adapters/*.py`)**:
  - Agar aapke paas VirusTotal ya AbuseIPDB ki paid/free API key abhi nahi hai, tab bhi app crash nahi karega! System automatically **`DEMO TELEMETRY`** badge ke saath realistic heuristic fallback use karta hai, aur jaise hi aap `.env` mein key daalte ho, **`LIVE INTEL`** mode activate ho jaata hai.

---

## Stage 3: Step-by-Step Commands (Kaise Run aur Test Karein?)

### 1. Database Start & Seed Karna
```bash
# Local PostgreSQL start karega (port 5433 par, bina sudo ke!)
./scripts/setup-local-pg.sh

# Prisma tables sync aur Demo SOC data seed karne ke liye:
cd backend
npx prisma db push
npm run prisma:seed
```

### 2. Teeno Services Ek Saath Start Karna
Root folder (`THREATLENS-AI/`) se:
```bash
./scripts/dev.sh
```
- **Frontend UI:** `http://localhost:5173`
- **Backend API Health:** `http://127.0.0.1:4000/api/health`
- **Python Engine Docs (Swagger):** `http://127.0.0.1:8088/docs`

### 3. Saare Automated Tests Run Karna
```bash
./scripts/test-all.sh
```
Yeh command:
1. Python FastAPI ke **9 pytest unit/security tests** run karegi.
2. Backend TypeScript build + **7 Supertest/Vitest integration tests** (Auth, CSRF, RBAC, SSRF, Scans, Graph, Admin) run karegi.
3. Frontend Vite production build + **3 React component tests** run karegi.

---

## Stage 4: Common Troubleshooting (Agar Error Aaye Toh Kya Karein?)

1. **`Port already in use (EADDRINUSE)`**:
   - Check karein koi purana process port `4000`, `5173`, ya `8088` par toh nahi chal raha:
     `ss -tulpn | grep -E '4000|5173|8088'`
2. **`Can't reach database server at 127.0.0.1:5433`**:
   - Root folder se `./scripts/setup-local-pg.sh` run karein (ya agar aap system/Docker Postgres port `5432` use kar rahe hain toh `backend/.env` mein `DATABASE_URL` update karein).
3. **Live Threat Intelligence API Keys Add Karna**:
   - `analysis-engine/.env` open karein aur jo bhi free keys aapke paas hain (`VIRUSTOTAL_API_KEY`, `ABUSEIPDB_API_KEY`, `ALIENVAULT_OTX_API_KEY`, `GOOGLE_SAFE_BROWSING_API_KEY`, `NVD_API_KEY`, `AI_API_KEY`) paste karke `./scripts/dev.sh` restart kar dein!
