// Server penyimpanan "Status Pesanan Bengkel" (Netlify Functions + Netlify Blobs).
//
// Prinsip: server TIDAK PERNAH melihat kata sandi, isi pesanan, atau isi foto.
// Semua itu dienkripsi di peramban sebelum dikirim. Server hanya menyimpan
// data terenkripsi, memeriksa bukti login, dan membatasi percobaan masuk.

const te = new TextEncoder();
const td = new TextDecoder();

const BATAS = { adm: 1500000, meta: 300000, foto: 2500000, badan: 5500000, pesananPerSimpan: 150 };
const TOKEN_UMUR = 2 * 60 * 60 * 1000; // sesi 2 jam, diperbarui otomatis oleh aplikasi
const KUNCI_MAKS = 5; // salah sandi berturut-turut dari satu alamat IP
const KUNCI_JENDELA = 15 * 60 * 1000;
const KUNCI_LAMA = 15 * 60 * 1000;
const GLOBAL_MAKS = 300; // batas kegagalan per jam dari semua IP
const GLOBAL_JENDELA = 60 * 60 * 1000;
const RE_ID = /^[0-9A-Z]{4}$/;
const RE_PID = /^[A-Za-z0-9_-]{1,32}$/;
const RE_B64 = /^[A-Za-z0-9+/=]+$/;

class Galat extends Error {
  constructor(status, kode, tambahan) {
    super(kode);
    this.status = status;
    this.kode = kode;
    this.tambahan = tambahan || {};
  }
}

/* ---------- Utilitas ---------- */
function json(data, status = 200, header = {}) {
  return new Response(JSON.stringify(Object.assign({ srv: 1 }, data)), {
    status,
    headers: Object.assign({ 'content-type': 'application/json; charset=utf-8', 'cache-control': 'no-store' }, header)
  });
}
const galat = (status, kode, tambahan) => json(Object.assign({ galat: kode }, tambahan || {}), status);

function b64(u8) {
  let s = '';
  for (let i = 0; i < u8.length; i += 0x8000) s += String.fromCharCode.apply(null, u8.subarray(i, i + 0x8000));
  return btoa(s);
}
function unb64(s) {
  const bin = atob(s);
  const u = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) u[i] = bin.charCodeAt(i);
  return u;
}
const b64url = u8 => b64(u8).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
function unb64url(s) {
  s = s.replace(/-/g, '+').replace(/_/g, '/');
  while (s.length % 4) s += '=';
  return unb64(s);
}
async function sha256hex(s) {
  const d = await crypto.subtle.digest('SHA-256', te.encode(s));
  return Array.from(new Uint8Array(d)).map(x => x.toString(16).padStart(2, '0')).join('');
}
function samaPersis(a, b) {
  if (typeof a !== 'string' || typeof b !== 'string' || a.length !== b.length) return false;
  let r = 0;
  for (let i = 0; i < a.length; i++) r |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return r === 0;
}
const str = (x, maks) => typeof x === 'string' && x.length <= maks;
const bulat = (x, min, maks) => Number.isInteger(x) && x >= min && x <= maks;

async function bacaJson(req) {
  const teks = await req.text();
  if (teks.length > BATAS.badan) throw new Galat(413, 'terlalu_besar');
  try { return JSON.parse(teks); } catch (e) { throw new Galat(400, 'json_rusak'); }
}

/* ---------- Validasi isi yang diterima ---------- */
function cekCipher(o, maks) {
  if (!o || typeof o !== 'object' || !str(o.iv, 64) || !str(o.ct, maks)) throw new Galat(400, 'data_tidak_valid');
  if (!o.ct.length || !RE_B64.test(o.ct) || !o.iv.length || !RE_B64.test(o.iv)) throw new Galat(400, 'data_tidak_valid');
  return { iv: o.iv, ct: o.ct };
}
function cekAdm(a) {
  if (!a || typeof a !== 'object' || !str(a.salt, 64) || !a.salt.length || !bulat(a.it, 100000, 5000000)) throw new Galat(400, 'data_tidak_valid');
  const c = cekCipher(a, BATAS.adm);
  return { salt: a.salt, it: a.it, iv: c.iv, ct: c.ct };
}
function cekPub(p) {
  if (!p || typeof p !== 'object' || !str(p.nama, 120) || !str(p.wa, 40)) throw new Galat(400, 'data_tidak_valid');
  return { nama: p.nama, wa: p.wa };
}
function cekAuth(a) {
  if (!str(a, 200) || a.length < 20) throw new Galat(400, 'data_tidak_valid');
  return a;
}

/* ---------- Sesi (token bertanda tangan) ---------- */
const kunciHmac = sk => crypto.subtle.importKey('raw', unb64(sk), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign', 'verify']);
async function buatToken(cfg, now) {
  const exp = now + TOKEN_UMUR;
  const p = b64url(te.encode(JSON.stringify({ exp })));
  const sig = new Uint8Array(await crypto.subtle.sign('HMAC', await kunciHmac(cfg.sk), te.encode(p)));
  return { token: p + '.' + b64url(sig), exp };
}
async function tokenSah(cfg, header, now) {
  const m = /^Bearer ([A-Za-z0-9_-]+)\.([A-Za-z0-9_-]+)$/.exec(header || '');
  if (!m || !cfg) return false;
  try {
    const ok = await crypto.subtle.verify('HMAC', await kunciHmac(cfg.sk), unb64url(m[2]), te.encode(m[1]));
    if (!ok) return false;
    const p = JSON.parse(td.decode(unb64url(m[1])));
    return typeof p.exp === 'number' && p.exp > now;
  } catch (e) { return false; }
}

/* ---------- Pembatasan percobaan masuk ---------- */
const ipDari = (req, context) =>
  (context && context.ip) || req.headers.get('x-nf-client-connection-ip') || (req.headers.get('x-forwarded-for') || '').split(',')[0].trim() || 'tidak-dikenal';
const kunciIp = async ip => 'rl/' + (await sha256hex('ip:' + ip)).slice(0, 40);

async function sisaKunci(store, ip, now) {
  const rec = await store.get(await kunciIp(ip), { type: 'json' });
  if (rec && rec.sampai > now) return Math.ceil((rec.sampai - now) / 1000);
  const g = await store.get('rl/semua', { type: 'json' });
  if (g && g.sampai > now) return Math.ceil((g.sampai - now) / 1000);
  return 0;
}
async function catatGagal(store, ip, now) {
  const k = await kunciIp(ip);
  let rec = await store.get(k, { type: 'json' });
  if (!rec || now - rec.mulai > KUNCI_JENDELA) rec = { n: 0, mulai: now, sampai: 0 };
  rec.n += 1;
  if (rec.n >= KUNCI_MAKS) rec.sampai = now + KUNCI_LAMA;
  await store.setJSON(k, rec);
  let g = await store.get('rl/semua', { type: 'json' });
  if (!g || now - g.mulai > GLOBAL_JENDELA) g = { n: 0, mulai: now, sampai: 0 };
  g.n += 1;
  if (g.n >= GLOBAL_MAKS) g.sampai = g.mulai + GLOBAL_JENDELA;
  await store.setJSON('rl/semua', g);
  return { sisa: Math.max(0, KUNCI_MAKS - rec.n), tunggu: rec.sampai > now ? Math.ceil((rec.sampai - now) / 1000) : 0 };
}

/* ---------- Penanganan permintaan ---------- */
export function buatHandler(ambilStore, opsi) {
  const sekarang = (opsi && opsi.sekarang) || (() => Date.now());
  let simpan = null;

  return async function handler(req, context) {
    try {
      if (!simpan) simpan = await ambilStore();
      const store = simpan;
      const now = sekarang();
      const url = new URL(req.url);
      const bag = url.pathname.split('/').filter(Boolean);
      if (bag[0] !== 'api') throw new Galat(404, 'tidak_ditemukan');
      const metode = req.method.toUpperCase();
      const a = bag[1], b = bag[2], c = bag[3];
      const cfg = await store.get('cfg', { type: 'json' });
      const butuhMasuk = async () => {
        if (!(await tokenSah(cfg, req.headers.get('authorization'), now))) throw new Galat(401, 'token');
      };

      // Status publik: ada akun atau belum, plus nama dan nomor WhatsApp bengkel.
      if (a === 'state' && metode === 'GET' && bag.length === 2) {
        return json({ ada: !!cfg, salt: cfg ? cfg.salt : undefined, it: cfg ? cfg.it : undefined, pub: cfg ? cfg.pub : {} });
      }

      // Buat akun pemilik (hanya bisa sekali).
      if (a === 'setup' && metode === 'POST' && bag.length === 2) {
        const j = await bacaJson(req);
        if (cfg) throw new Galat(409, 'sudah_ada');
        const adm = cekAdm(j.adm);
        const pub = cekPub(j.pub);
        const auth = cekAuth(j.auth);
        if (!str(j.salt, 64) || !j.salt.length || !bulat(j.it, 100000, 5000000)) throw new Galat(400, 'data_tidak_valid');
        const baru = {
          salt: j.salt, it: j.it, verifier: await sha256hex(auth),
          sk: b64(crypto.getRandomValues(new Uint8Array(32))),
          pub, adm, ids: [], rev: 1, dibuat: now
        };
        await store.setJSON('cfg', baru);
        const t = await buatToken(baru, now);
        return json({ token: t.token, exp: t.exp, rev: baru.rev }, 201);
      }

      // Masuk: bukti login (turunan kata sandi) dicocokkan dengan sidik jari yang tersimpan.
      if (a === 'login' && metode === 'POST' && bag.length === 2) {
        const j = await bacaJson(req);
        const ip = ipDari(req, context);
        const tunggu = await sisaKunci(store, ip, now);
        if (tunggu) throw new Galat(429, 'terkunci', { tunggu });
        if (!cfg) throw new Galat(404, 'belum_ada');
        const auth = typeof j.auth === 'string' ? j.auth.slice(0, 200) : '';
        if (!samaPersis(await sha256hex(auth), cfg.verifier)) {
          const r = await catatGagal(store, ip, now);
          throw new Galat(401, 'salah', r);
        }
        await store.delete(await kunciIp(ip));
        const t = await buatToken(cfg, now);
        return json({ token: t.token, exp: t.exp, rev: cfg.rev });
      }

      // Data pemilik (hanya setelah masuk).
      if (a === 'admin' && metode === 'GET' && bag.length === 2) {
        await butuhMasuk();
        return json({ rev: cfg.rev, pub: cfg.pub, adm: cfg.adm, ids: cfg.ids });
      }
      if (a === 'ord' && metode === 'GET' && bag.length === 2) {
        await butuhMasuk();
        const ids = (url.searchParams.get('ids') || '').split(',').filter(Boolean);
        if (ids.length > 40 || ids.some(x => !RE_ID.test(x))) throw new Galat(400, 'data_tidak_valid');
        const hasil = {};
        await Promise.all(ids.map(async id => {
          const o = await store.get('ord/' + id, { type: 'json' });
          if (o && o.m) hasil[id] = { m: o.m };
        }));
        return json({ ord: hasil });
      }

      // Simpan perubahan.
      if (a === 'save' && metode === 'POST' && bag.length === 2) {
        await butuhMasuk();
        const j = await bacaJson(req);
        if (j.rev !== cfg.rev) throw new Galat(409, 'konflik', { rev: cfg.rev });
        const ord = j.ord && typeof j.ord === 'object' ? j.ord : {};
        const idsOrd = Object.keys(ord);
        if (idsOrd.length > BATAS.pesananPerSimpan) throw new Galat(413, 'terlalu_besar');
        const upsert = {};
        for (const id of idsOrd) {
          if (!RE_ID.test(id) || !ord[id]) throw new Galat(400, 'data_tidak_valid');
          upsert[id] = cekCipher(ord[id].m, BATAS.meta);
        }
        const hapus = Array.isArray(j.del) ? j.del : [];
        if (hapus.length > 500 || hapus.some(x => !RE_ID.test(x))) throw new Galat(400, 'data_tidak_valid');
        const hapusFoto = Array.isArray(j.delFoto) ? j.delFoto : [];
        if (hapusFoto.length > 2000) throw new Galat(400, 'data_tidak_valid');
        for (const k of hapusFoto) {
          const p = typeof k === 'string' ? k.split('/') : [];
          if (p.length !== 2 || !RE_ID.test(p[0]) || !RE_PID.test(p[1])) throw new Galat(400, 'data_tidak_valid');
        }
        const adm = j.adm !== undefined ? cekAdm(j.adm) : null;
        const pub = j.pub !== undefined ? cekPub(j.pub) : null;
        let cred = null;
        if (j.cred !== undefined) {
          const k = j.cred;
          if (!k || !str(k.salt, 64) || !k.salt.length || !bulat(k.it, 100000, 5000000)) throw new Galat(400, 'data_tidak_valid');
          cred = { salt: k.salt, it: k.it, auth: cekAuth(k.auth) };
        }

        for (const id of idsOrd) {
          await store.setJSON('ord/' + id, { m: upsert[id] });
          if (cfg.ids.indexOf(id) < 0) cfg.ids.push(id);
        }
        for (const id of hapus) {
          await store.delete('ord/' + id);
          cfg.ids = cfg.ids.filter(x => x !== id);
          try {
            const daftar = await store.list({ prefix: 'foto/' + id + '/' });
            for (const x of (daftar && daftar.blobs) || []) await store.delete(x.key);
          } catch (e) { /* pembersihan foto yatim tidak boleh menggagalkan simpan */ }
        }
        for (const k of hapusFoto) await store.delete('foto/' + k);
        if (adm) cfg.adm = adm;
        if (pub) cfg.pub = pub;
        if (cred) {
          cfg.salt = cred.salt;
          cfg.it = cred.it;
          cfg.verifier = await sha256hex(cred.auth);
          cfg.sk = b64(crypto.getRandomValues(new Uint8Array(32))); // semua sesi lama otomatis tidak berlaku
        }
        cfg.rev += 1;
        await store.setJSON('cfg', cfg);
        const hasil = { rev: cfg.rev };
        if (cred) {
          const t = await buatToken(cfg, now);
          hasil.token = t.token;
          hasil.exp = t.exp;
        }
        return json(hasil);
      }

      // Halaman pelanggan: satu pesanan menurut kode. Isinya terenkripsi, hanya kode lengkap yang bisa membukanya.
      if (a === 'o' && metode === 'GET' && bag.length === 3) {
        if (!RE_ID.test(b)) throw new Galat(404, 'tidak_ditemukan');
        const o = await store.get('ord/' + b, { type: 'json' });
        if (!o || !o.m) throw new Galat(404, 'tidak_ditemukan');
        return json({ m: o.m });
      }

      // Foto terenkripsi.
      if (a === 'f' && bag.length === 4 && RE_ID.test(b) && RE_PID.test(c)) {
        if (metode === 'GET') {
          const f = await store.get('foto/' + b + '/' + c, { type: 'json' });
          if (!f) throw new Galat(404, 'tidak_ditemukan');
          return json({ iv: f.iv, ct: f.ct }, 200, { 'cache-control': 'public, max-age=86400' });
        }
        if (metode === 'PUT') {
          await butuhMasuk();
          const j = await bacaJson(req);
          await store.setJSON('foto/' + b + '/' + c, cekCipher(j, BATAS.foto));
          return json({ ok: true });
        }
      }

      throw new Galat(404, 'tidak_ditemukan');
    } catch (e) {
      if (e instanceof Galat) return galat(e.status, e.kode, e.tambahan);
      console.error('Kesalahan server:', e);
      return galat(500, 'server');
    }
  };
}

/* ---------- Pintu masuk Netlify ---------- */
let handlerNetlify = null;
export default async function (req, context) {
  if (!handlerNetlify) {
    handlerNetlify = buatHandler(async () => {
      const { getStore } = await import('@netlify/blobs');
      return getStore({ name: 'bengkel', consistency: 'strong' });
    });
  }
  return handlerNetlify(req, context);
}

export const config = { path: '/api/*' };
