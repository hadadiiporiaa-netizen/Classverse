import 'dotenv/config';
import express from 'express';
import cors from 'cors';
import helmet from 'helmet';
import session from 'express-session';
import rateLimit from 'express-rate-limit';
import multer from 'multer';
import sharp from 'sharp';
import crypto from 'node:crypto';
import fs from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { AccessToken, RoomServiceClient } from 'livekit-server-sdk';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const uploadDir = path.join(__dirname, 'uploads');
await fs.mkdir(uploadDir, { recursive: true });
const app = express();
app.disable('x-powered-by');
app.use(helmet({ crossOriginResourcePolicy: { policy: 'cross-origin' }, contentSecurityPolicy: false }));
app.use(cors({ origin: process.env.CLIENT_ORIGIN || 'http://localhost:5173', credentials: true }));
app.use(express.json({ limit: '20kb' }));
if (!process.env.SESSION_SECRET || process.env.SESSION_SECRET.length < 32) {
  console.warn('WARNING: Set SESSION_SECRET to a random value of at least 32 characters in .env');
}
app.use(session({
  name: 'classverse.sid',
  secret: process.env.SESSION_SECRET || 'dev-only-change-this-secret-please-123456789',
  resave: false, saveUninitialized: false,
  cookie: { httpOnly: true, sameSite: 'strict', secure: process.env.NODE_ENV === 'production', maxAge: 2 * 60 * 60 * 1000 }
}));

const { LIVEKIT_URL, LIVEKIT_API_KEY, LIVEKIT_API_SECRET } = process.env;
const MAX_PARTICIPANTS = Number(process.env.MAX_PARTICIPANTS || 5);
const roomService = LIVEKIT_URL && LIVEKIT_API_KEY && LIVEKIT_API_SECRET
  ? new RoomServiceClient(LIVEKIT_URL, LIVEKIT_API_KEY, LIVEKIT_API_SECRET) : null;

let logoFilename = null;
try { logoFilename = (await fs.readFile(path.join(uploadDir, 'logo-current.json'), 'utf8')).trim() || null; } catch {}

app.get('/api/site-config', (_req, res) => res.json({ siteName: 'کلاس‌ورس', logoUrl: logoFilename ? `/uploads/${encodeURIComponent(logoFilename)}` : null }));
app.use('/uploads', express.static(uploadDir, { dotfiles: 'deny', index: false, maxAge: '1h' }));

const loginLimiter = rateLimit({ windowMs: 15 * 60 * 1000, limit: 8, standardHeaders: true, legacyHeaders: false });
app.post('/api/admin/login', loginLimiter, (req, res) => {
  const configured = process.env.ADMIN_PASSWORD;
  if (!configured || configured === 'replace_this_with_a_long_unique_password') return res.status(503).json({ error: 'ابتدا ADMIN_PASSWORD را در تنظیمات سرور تعیین کن.' });
  const provided = String(req.body?.password || '');
  const a = Buffer.from(provided), b = Buffer.from(configured);
  if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) return res.status(401).json({ error: 'رمز عبور درست نیست.' });
  req.session.isAdmin = true;
  req.session.csrfToken = crypto.randomBytes(32).toString('hex');
  req.session.save(err => {
    if (err) return res.status(500).json({ error: 'ساخت نشست امن ناموفق بود.' });
    res.json({ ok: true, csrfToken: req.session.csrfToken });
  });
});
function requireAdmin(req, res, next) {
  if (!req.session?.isAdmin) return res.status(401).json({ error: 'ابتدا وارد پنل مدیریت شو.' });
  const token = String(req.get('X-CSRF-Token') || '');
  if (!token || token !== req.session.csrfToken) return res.status(403).json({ error: 'درخواست امنیتی معتبر نیست؛ دوباره وارد شو.' });
  next();
}
app.post('/api/admin/logout', requireAdmin, (req, res) => req.session.destroy(() => res.json({ ok: true })));

const memoryUpload = multer({
  storage: multer.memoryStorage(), limits: { fileSize: 2 * 1024 * 1024, files: 1 },
  fileFilter: (_req, file, cb) => {
    const allowed = ['image/png', 'image/jpeg', 'image/webp', 'image/svg+xml'];
    if (!allowed.includes(file.mimetype)) return cb(new Error('فقط PNG، JPG، WebP یا SVG مجاز است.'));
    cb(null, true);
  }
});
app.post('/api/admin/logo', requireAdmin, (req, res) => {
  memoryUpload.single('logo')(req, res, async err => {
    try {
      if (err) return res.status(400).json({ error: err.message || 'فایل قابل قبول نیست.' });
      if (!req.file) return res.status(400).json({ error: 'فایل لوگو انتخاب نشده است.' });
      const extMap = { 'image/png': '.png', 'image/jpeg': '.jpg', 'image/webp': '.webp' };
      let ext = extMap[req.file.mimetype];
      let buffer = req.file.buffer;
      if (req.file.mimetype === 'image/svg+xml') {
        let svg = buffer.toString('utf8');
        if (svg.length > 1024 * 1024 || !/<svg\b/i.test(svg) || /<script\b|on\w+\s*=|javascript:|<foreignObject\b|<!ENTITY/i.test(svg)) {
          return res.status(400).json({ error: 'این SVG امن یا معتبر تشخیص داده نشد؛ لطفاً PNG یا WebP آپلود کن.' });
        }
        ext = '.svg';
      } else {
        const meta = await sharp(buffer, { limitInputPixels: 20_000_000 }).metadata();
        if (!['png', 'jpeg', 'webp'].includes(meta.format)) return res.status(400).json({ error: 'محتوای فایل با فرمت مجاز مطابقت ندارد.' });
        buffer = await sharp(buffer, { limitInputPixels: 20_000_000 }).rotate().resize({ width: 1200, height: 1200, fit: 'inside', withoutEnlargement: true }).toBuffer();
      }
      const filename = `logo-${crypto.randomBytes(12).toString('hex')}${ext}`;
      await fs.writeFile(path.join(uploadDir, filename), buffer, { flag: 'wx', mode: 0o644 });
      await fs.writeFile(path.join(uploadDir, 'logo-current.json'), filename, { mode: 0o600 });
      logoFilename = filename;
      res.json({ siteName: 'کلاس‌ورس', logoUrl: `/uploads/${encodeURIComponent(filename)}` });
    } catch (e) {
      console.error(e);
      res.status(500).json({ error: 'ذخیره لوگو انجام نشد.' });
    }
  });
});

app.get('/api/health', (_req, res) => res.json({ ok: true }));
app.post('/api/token', async (req, res) => {
  try {
    if (!roomService) return res.status(503).json({ error: 'تنظیمات LiveKit در سرور کامل نشده است.' });
    const roomName = String(req.body?.roomName || '').trim(), participantName = String(req.body?.participantName || '').trim();
    if (!/^[a-zA-Z0-9_-]{3,80}$/.test(roomName)) return res.status(400).json({ error: 'کد کلاس باید ۳ تا ۸۰ نویسه انگلیسی، عدد، خط تیره یا زیرخط باشد.' });
    if (!participantName || participantName.length > 60) return res.status(400).json({ error: 'نام شرکت‌کننده را وارد کن.' });
    let rooms = await roomService.listRooms([roomName]); let room = rooms.find(r => r.name === roomName);
    if (!room) { try { room = await roomService.createRoom({ name: roomName, maxParticipants: MAX_PARTICIPANTS, emptyTimeout: 600 }); } catch { rooms = await roomService.listRooms([roomName]); room = rooms.find(r => r.name === roomName); } }
    const participants = await roomService.listParticipants(roomName);
    if (participants.length >= MAX_PARTICIPANTS) return res.status(409).json({ error: 'ظرفیت کلاس تکمیل است؛ حداکثر ۵ نفر.' });
    const token = new AccessToken(LIVEKIT_API_KEY, LIVEKIT_API_SECRET, { identity: crypto.randomUUID(), name: participantName, ttl: '2h' });
    token.addGrant({ roomJoin: true, room: roomName, canPublish: true, canSubscribe: true, canPublishData: true });
    res.json({ serverUrl: LIVEKIT_URL, token: await token.toJwt(), roomName });
  } catch (e) { console.error(e); res.status(500).json({ error: 'خطای سرور هنگام آماده‌سازی کلاس.' }); }
});

app.use((err, _req, res, _next) => {
  console.error(err);
  res.status(500).json({ error: 'خطای غیرمنتظره سرور.' });
});
const port = Number(process.env.PORT || 3001);
app.listen(port, () => console.log(`ClassVerse API running on http://localhost:${port}`));
