const express = require('express');
const mysql = require('mysql2'); 
const fs = require('fs');
const path = require('path'); 
const multer = require('multer');
require('dotenv').config();

// === TAMBAHAN BCRYPT ===
const bcrypt = require('bcrypt');
// =======================

// --- ALAT KEAMANAN BARU ---
const jwt = require('jsonwebtoken');
const { body, validationResult } = require('express-validator'); 
const KEY_NODEJS = process.env.KEY_NODE_JS || process.env.key_node_js || process.env.JWT_SECRET;
if (!KEY_NODEJS) {
    console.error("PERINGATAN KEAMANAN: Variabel KEY_NODE_JS belum disetel di file .env!");
}

// Pastikan folder uploads tersedia di direktori lokal backend
const uploadsDir = path.join(__dirname, 'uploads');
if (!fs.existsSync(uploadsDir)) {
  fs.mkdirSync(uploadsDir, { recursive: true });
}

// Konfigurasi Multer untuk penyimpanan lokal di folder uploads
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    cb(null, uploadsDir);
  },
  filename: (req, file, cb) => {
    const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1E9);
    const ext = path.extname(file.originalname);
    cb(null, file.fieldname + '-' + uniqueSuffix + ext);
  }
});

const fileFilter = (req, file, cb) => {
    const allowedExts = /jpeg|jpg|png|webp|pdf/;
    const ext = path.extname(file.originalname).toLowerCase().replace('.', '');
    const mime = (file.mimetype || '').toLowerCase();

    const isExtAllowed = allowedExts.test(ext);
    const isMimeAllowed = mime.startsWith('image/') || mime === 'application/pdf';

    if (isExtAllowed && isMimeAllowed) {
        return cb(null, true);
    }
    cb(new Error('Format file tidak didukung! Hanya diperbolehkan berkas gambar (JPG, PNG, WEBP) atau dokumen PDF.'));
};

const upload = multer({ 
    storage: storage,
    limits: { fileSize: 5 * 1024 * 1024 },
    fileFilter: fileFilter
});

// Helper pembersih file lokal di folder uploads saat data diupdate atau dihapus
const hapusFileLokal = (fileIdentifier) => {
    if (!fileIdentifier || typeof fileIdentifier !== 'string') return;
    try {
        // Abaikan data lama yang masih berupa URL web (http/https)
        if (fileIdentifier.startsWith('http://') || fileIdentifier.startsWith('https://')) {
            return;
        }

        const namaFileBersih = path.basename(fileIdentifier);
        const filePath = path.join(uploadsDir, namaFileBersih);
        if (fs.existsSync(filePath)) {
            fs.unlink(filePath, (err) => {
                if (err) console.error('Gagal menghapus file lokal:', err.message);
            });
        }
    } catch (err) {
        console.error('Error saat menghapus file lokal:', err.message);
    }
};

const app = express();

app.use((req, res, next) => {
    const allowedOrigin = req.headers.origin || "*";
    res.setHeader('Access-Control-Allow-Origin', allowedOrigin);
    
    res.setHeader('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');
    res.setHeader('Access-Control-Allow-Credentials', 'true');

    if (req.method === 'OPTIONS') {
        return res.status(200).end();
    }
    next();
});

app.use(express.json()); 

app.use('/uploads', express.static(path.join(__dirname, 'uploads')));

// === MENGGUNAKAN POOL AGAR SERVER TIDAK MATI SAAT MYSQL TERPUTUS ===
const db = mysql.createPool({
    host: process.env.DB_HOST || 'localhost',
    port: Number(process.env.DB_PORT) || 3306,
    user: process.env.DB_USER || 'root',
    password: process.env.DB_PASSWORD || '', 
    database: process.env.DB_NAME || 'db_one_ekbang',
    dateStrings: true,
    timezone: '+07:00',
    waitForConnections: true,
    connectionLimit: 10,
    queueLimit: 0
});

db.getConnection((err, conn) => {
    if (err) {
        console.log('Waduh, gagal masuk gudang:', err.message);
    } else {
        console.log('DATABASE MYSQL aman terkoneksi! 🗄️');
        // Menjamin tersedianya kolom status (Aktif/Non-Aktif) pada data_petugas
        conn.query("SHOW COLUMNS FROM data_petugas LIKE 'status'", (errCol, rows) => {
            if (!errCol && rows && rows.length === 0) {
                conn.query("ALTER TABLE data_petugas ADD COLUMN status VARCHAR(20) DEFAULT 'Aktif'", (errAlter) => {
                    conn.release();
                    if (errAlter) console.error("Gagal menambahkan kolom status:", errAlter.message);
                    else console.log("Kolom status petugas berhasil disiapkan! ✅");
                });
            } else {
                conn.release();
            }
        });
    }
});

db.on('error', (err) => {
    console.error('Koneksi pool database mengalami error tak terduga:', err.message);
});

// === TARGET 1: SATPAM PENGECEK KUNCI (MIDDLEWARE JWT) ===
const cekToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1]; 

    if (!token) {
        return res.status(401).json({ status: "gagal", pesan: "Akses Ditolak! Anda harus Login." });
    }

    jwt.verify(token, KEY_NODEJS, (err, user) => {
        if (err) {
            return res.status(403).json({ status: "gagal", pesan: "Akses Ilegal! Token palsu/kedaluwarsa!" });
        }
        req.user = user;
        next(); 
    });
};

const hapusFileSampah = (fileObj) => {
    if (!fileObj) return;
    if (fileObj.path && fs.existsSync(fileObj.path)) {
        fs.unlink(fileObj.path, () => {});
    }
};

// === TARGET 2: MESIN X-RAY (MIDDLEWARE VALIDASI INPUT) ===
const cekValidasi = (req, res, next) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        // Hapus file yang terlanjur terupload jika validasi teks gagal
        if (req.file) hapusFileSampah(req.file);
        if (req.files) {
            Object.values(req.files).flat().forEach(f => hapusFileSampah(f));
        }
        return res.status(400).json({ status: "gagal", pesan: errors.array()[0].msg });
    }
    next();
};

// === TARGET 3: PENANGKAL DOUBLE-SUBMIT (IDEMPOTENCY SEDERHANA) ===
const requestCache = new Map();

// Pembersih memori otomatis setiap 30 detik
setInterval(() => {
    const now = Date.now();
    for (const [key, timestamp] of requestCache.entries()) {
        if (now - timestamp > 5000) {
            requestCache.delete(key);
        }
    }
}, 30000);

const antiDoubleSubmit = (req, res, next) => {
    const clientIp = req.ip || req.headers['x-forwarded-for'] || req.socket?.remoteAddress || 'unknown';
    const bodyIdentitas = req.body ? (req.body.nik || req.body.petugas_id || req.body.nama || req.body.judul_agenda || req.body.nama_lokasi || req.body.username || '') : '';
    const sidikJari = `${clientIp}_${req.method}_${req.originalUrl}_${bodyIdentitas}`;

    const now = Date.now();
    if (requestCache.has(sidikJari)) {
        const waktuTerakhir = requestCache.get(sidikJari);
        // Jika permintaan persis sama masuk kurang dari 3 detik (double click cepat)
        if (now - waktuTerakhir < 3000) {
            if (req.file) hapusFileSampah(req.file);
            if (req.files) Object.values(req.files).flat().forEach(hapusFileSampah);
            return res.status(429).json({
                status: "gagal",
                pesan: "Permintaan sedang diproses! Harap tunggu beberapa detik dan jangan menekan tombol berulang kali."
            });
        }
    }

    requestCache.set(sidikJari, now);
    next();
};

app.get('/', (req, res) => {
    res.send('API Backend Ekbang Berjalan Normal! 🚀');
});

app.get('/admin', cekToken, (req,res) => {
    const usersSQL = 'SELECT id, nik, nama_lengkap, username FROM admin';
    db.query(usersSQL, (err,hasil) => {
        if(err) return res.status(500).json({ status: "error", pesan: "Gagal mengambil data staf admin dari database." });
        res.json(hasil);
    });
});

// Rute POST Admin (DIGEMBOK & DIVALIDASI KETAT)
// === TAMBAHAN BCRYPT: Mengubah callback menjadi async ===
app.post('/admin', cekToken, [
    body('nik').isNumeric().withMessage('NIK wajib berupa angka!').isLength({ min: 16, max: 16 }).withMessage('NIK harus persis 16 digit!'),
    body('nama_lengkap').trim().escape().notEmpty().withMessage('Nama lengkap wajib diisi!'),
    body('username').trim().escape().notEmpty(),
    body('password').notEmpty()
], cekValidasi, antiDoubleSubmit, async (req, res) => {
    const { nik, nama_lengkap, username, password } = req.body;
    
    try {
        // === TAMBAHAN BCRYPT: Mengacak password sebelum disimpan ===
        const saltRounds = 10;
        const hashedPassword = await bcrypt.hash(password, saltRounds);
        
        const sql = `INSERT INTO admin (nik, nama_lengkap, username, password) VALUES (?, ?, ?, ?)`;
        // === TAMBAHAN BCRYPT: Kirim hashedPassword, BUKAN password asli ===
        db.query(sql, [nik, nama_lengkap, username, hashedPassword], (err, result) => {
            if (err) {
                if (err.code === 'ER_DUP_ENTRY') {
                    return res.status(400).json({ status: "gagal", pesan: "NIK atau Username sudah terdaftar di sistem!" });
                }
                return res.status(500).json({ status: "error", pesan: "Gagal membuat akun." });
            }
            res.json({ status: "sukses", pesan: "Akun staf baru berhasil dibuat!" });
        });
    } catch (error) {
        return res.status(500).json({ status: "error", pesan: "Gagal mengamankan password." });
    }
});

app.delete('/admin/:id', cekToken, (req, res) => {
    const idAdmin = req.params.id;

    // Cegah admin menghapus akunnya sendiri yang sedang aktif login
    if (req.user && String(req.user.id) === String(idAdmin)) {
        return res.status(400).json({ status: "gagal", pesan: "Anda tidak dapat menghapus akun Anda sendiri yang sedang aktif digunakan!" });
    }

    // Pastikan tidak menghapus akun admin terakhir di sistem
    db.query("SELECT COUNT(*) AS totalAdmin FROM admin", (errCount, countRows) => {
        if (errCount) return res.status(500).json({ status: "error", pesan: "Gagal memeriksa jumlah akun staf admin." });
        const total = countRows[0]?.totalAdmin || 0;
        if (total <= 1) {
            return res.status(400).json({ status: "gagal", pesan: "Tidak dapat menghapus akun admin terakhir! Minimal harus ada 1 akun staf di sistem." });
        }

        const sql = "DELETE FROM admin WHERE id = ?";
        db.query(sql, [idAdmin], (err, result) => {
            if (err) return res.status(500).json({ status: "error", pesan: "Gagal menghapus akun." });
            res.json({ status: "sukses", pesan: "Akses akun staf berhasil dicabut secara permanen!" });
        });
    });
});

app.post('/layanan', upload.fields([
    { name: 'foto_ktp', maxCount: 1 }, { name: 'foto_kk', maxCount: 1 }, { name: 'surat_pengantar', maxCount: 1 },
    { name: 'sertifikat_tanah', maxCount: 1 }, { name: 'foto_kondisi_rumah', maxCount: 1 }, { name: 'foto_lokasi', maxCount: 1 },
    { name: 'sk_buruan_sae', maxCount: 1 }, { name: 'kebutuhan_tanaman', maxCount: 1 }, { name: 'dokumen_a1', maxCount: 1 },
    { name: 'dokumen_a2', maxCount: 1 }, { name: 'foto_rembuk', maxCount: 1 }, { name: 'daftar_hadir', maxCount: 1 },
    { name: 'ba_muskel', maxCount: 1 }, { name: 'foto_muskel', maxCount: 1 }, { name: 'foto_halaman', maxCount: 1 },
    { name: 'proposal_sarpras', maxCount: 1 }, { name: 'foto_sarpras', maxCount: 1 }
]), [
    body('nik').isNumeric().withMessage('NIK wajib berupa angka!').isLength({ min: 16, max: 16 }).withMessage('NIK harus persis 16 digit!'),
    body('nama').trim().escape()
], cekValidasi, antiDoubleSubmit, (req, res) => {
    const { nik, nama, no_telepon = null, jenisLayanan = null } = req.body;
    const getNamaFile = (namaField) => req.files && req.files[namaField] ? req.files[namaField][0].filename : null;

    const dataKirim = [
        nik, nama, no_telepon, jenisLayanan, getNamaFile('foto_ktp'), getNamaFile('foto_kk'), getNamaFile('surat_pengantar'), 
        getNamaFile('sertifikat_tanah'), getNamaFile('foto_kondisi_rumah'), getNamaFile('foto_lokasi'), getNamaFile('sk_buruan_sae'), getNamaFile('kebutuhan_tanaman'), 
        getNamaFile('dokumen_a1'), getNamaFile('dokumen_a2'), getNamaFile('foto_rembuk'), getNamaFile('daftar_hadir'), getNamaFile('ba_muskel'), getNamaFile('foto_muskel'),
        getNamaFile('foto_halaman'), getNamaFile('proposal_sarpras'), getNamaFile('foto_sarpras')
    ];

    const tambahLayananSQL = `INSERT INTO pengajuan_layanan 
        (nik_pemohon, nama_pemohon, no_telepon, jenis_layanan, foto_ktp, foto_kk, surat_pengantar, sertifikat_tanah, foto_kondisi_rumah, foto_lokasi, sk_buruan_sae, kebutuhan_tanaman, dokumen_a1, dokumen_a2, foto_rembuk, daftar_hadir, ba_muskel, foto_muskel, foto_halaman, proposal_sarpras, foto_sarpras) 
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`; 
    
    db.query(tambahLayananSQL, dataKirim, (err, hasil) => {
        if(err) return res.status(500).json({ status: "error", pesan: "Gagal menyimpan data baru ke database!" });
        res.json({ status: 'sukses', pesan: 'Data layanan berhasil ditambahkan!', hasil: hasil });
    });
});

app.get('/layanan', cekToken, (req, res) => {
    const sql = `SELECT * FROM pengajuan_layanan ORDER BY tanggal_pengajuan DESC`;
    db.query(sql, (err, results) => {
        if (err) return res.status(500).json({ status: 'error', pesan: 'Gagal ambil data pengajuan.' });
        res.status(200).json({ status: 'sukses', data: results });
    });
});

const uploadLayananEdit = upload.fields([
    { name: 'foto_ktp', maxCount: 1 }, { name: 'foto_kk', maxCount: 1 }, { name: 'surat_pengantar', maxCount: 1 },
    { name: 'sertifikat_tanah', maxCount: 1 }, { name: 'foto_kondisi_rumah', maxCount: 1 }, { name: 'foto_lokasi', maxCount: 1 },
    { name: 'sk_buruan_sae', maxCount: 1 }, { name: 'kebutuhan_tanaman', maxCount: 1 }, { name: 'dokumen_a1', maxCount: 1 },
    { name: 'dokumen_a2', maxCount: 1 }, { name: 'foto_rembuk', maxCount: 1 }, { name: 'daftar_hadir', maxCount: 1 },
    { name: 'ba_muskel', maxCount: 1 }, { name: 'foto_muskel', maxCount: 1 }, { name: 'foto_halaman', maxCount: 1 },
    { name: 'proposal_sarpras', maxCount: 1 }, { name: 'foto_sarpras', maxCount: 1 }
]);

app.put('/layanan/:id', cekToken, uploadLayananEdit, [
    body('nik_pemohon').optional({ checkFalsy: true }).isNumeric().withMessage('NIK wajib berupa angka!').isLength({ min: 16, max: 16 }).withMessage('NIK harus persis 16 digit!'),
    body('nama_pemohon').optional({ checkFalsy: true }).trim().escape(),
    body('no_telepon').optional({ checkFalsy: true }).trim(),
    body('status').optional({ checkFalsy: true }).trim()
], cekValidasi, (req, res) => {
    const id = req.params.id;
    const { status, nik_pemohon, nama_pemohon, no_telepon } = req.body;

    const fileFields = [
        'foto_ktp', 'foto_kk', 'surat_pengantar', 'sertifikat_tanah', 'foto_kondisi_rumah',
        'foto_lokasi', 'sk_buruan_sae', 'kebutuhan_tanaman', 'dokumen_a1', 'dokumen_a2',
        'foto_rembuk', 'daftar_hadir', 'ba_muskel', 'foto_muskel', 'foto_halaman',
        'proposal_sarpras', 'foto_sarpras'
    ];

    const uploadedFiles = {};
    if (req.files) {
        for (const f of fileFields) {
            if (req.files[f] && req.files[f][0]) {
                uploadedFiles[f] = req.files[f][0].filename;
            }
        }
    }

    const hasFiles = Object.keys(uploadedFiles).length > 0;

    // Jika hanya status yang dikirim (misal dari tombol cepat Proses/Selesai) tanpa perubahan berkas/data lain
    if (status && !nik_pemohon && !nama_pemohon && !no_telepon && !hasFiles) {
        const sql = `UPDATE pengajuan_layanan SET status = ? WHERE id = ?`;
        return db.query(sql, [status, id], (err, hasil) => {
            if (err) return res.status(500).json({ status: 'error', pesan: 'Gagal memperbarui status.' });
            res.status(200).json({ status: 'sukses', pesan: 'Status pengajuan berhasil diperbarui!' });
        });
    }

    // Jika terdapat berkas dokumen baru yang diunggah untuk menggantikan berkas lama
    if (hasFiles) {
        const colsToSelect = Object.keys(uploadedFiles).join(', ');
        db.query(`SELECT ${colsToSelect} FROM pengajuan_layanan WHERE id = ?`, [id], (errOld, oldRows) => {
            if (!errOld && oldRows && oldRows[0]) {
                for (const col of Object.keys(uploadedFiles)) {
                    if (oldRows[0][col]) {
                        hapusFileLokal(oldRows[0][col]);
                    }
                }
            }

            const setClauses = [
                'nik_pemohon = COALESCE(?, nik_pemohon)',
                'nama_pemohon = COALESCE(?, nama_pemohon)',
                'no_telepon = COALESCE(?, no_telepon)',
                'status = COALESCE(?, status)'
            ];
            const values = [nik_pemohon || null, nama_pemohon || null, no_telepon || null, status || null];

            for (const [col, pathVal] of Object.entries(uploadedFiles)) {
                setClauses.push(`${col} = ?`);
                values.push(pathVal);
            }
            values.push(id);

            const sql = `UPDATE pengajuan_layanan SET ${setClauses.join(', ')} WHERE id = ?`;
            db.query(sql, values, (err, hasil) => {
                if (err) return res.status(500).json({ status: 'error', pesan: 'Gagal memperbarui data pengajuan.' });
                res.status(200).json({ status: 'sukses', pesan: 'Data pengajuan beserta dokumen berhasil diperbarui!' });
            });
        });
    } else {
        // Jika hanya memperbarui teks data pemohon
        const sql = `UPDATE pengajuan_layanan SET 
            nik_pemohon = COALESCE(?, nik_pemohon),
            nama_pemohon = COALESCE(?, nama_pemohon),
            no_telepon = COALESCE(?, no_telepon),
            status = COALESCE(?, status)
            WHERE id = ?`;

        db.query(sql, [nik_pemohon || null, nama_pemohon || null, no_telepon || null, status || null, id], (err, hasil) => {
            if (err) return res.status(500).json({ status: 'error', pesan: 'Gagal memperbarui data pengajuan.' });
            res.status(200).json({ status: 'sukses', pesan: 'Data pengajuan pemohon berhasil diperbarui!' });
        });
    }
});

// RUTE POST LOGIN (TERBUKA UTK PUBLIK + MENCETAK TOKEN)
app.post('/login', [
    body('username').trim().escape().notEmpty().withMessage('Username wajib diisi!'),
    body('password').notEmpty().withMessage('Password wajib diisi!')
], cekValidasi, antiDoubleSubmit, (req, res) => {
    const { username, password } = req.body;
    
    // === TAMBAHAN BCRYPT: Hanya cari username-nya saja ===
    const sql = `SELECT * FROM admin WHERE username = ?`;
    
    db.query(sql, [username], async (err, hasil) => {
        if (err) return res.status(500).json({ status: 'error', pesan: 'Kesalahan server' });
        
        if (hasil.length > 0) {
            const adminData = hasil[0];
            let passwordCocok = false;
            
            // === TAMBAHAN BCRYPT: Logika Anti-Terkunci (Auto-Upgrade Password) ===
            try {
                if (adminData.password && (adminData.password.startsWith('$2a$') || adminData.password.startsWith('$2b$') || adminData.password.startsWith('$2y$'))) {
                    passwordCocok = await bcrypt.compare(password, adminData.password);
                } else {
                    // MASA TRANSISI: Jika password di database masih teks biasa (contoh: 'useradmin')
                    if (password === adminData.password) {
                        passwordCocok = true;
                        
                        // Langsung otomatis enkripsi password lamanya di latar belakang
                        const hashedPassword = await bcrypt.hash(password, 10);
                        db.query('UPDATE admin SET password = ? WHERE id = ?', [hashedPassword, adminData.id]);
                    }
                }
                
                if (passwordCocok) {
                    if (!KEY_NODEJS) {
                        return res.status(500).json({ status: 'error', pesan: 'Konfigurasi server: Kunci JWT (KEY_NODE_JS) belum disetel di file .env!' });
                    }
                    delete adminData.password; // Jangan kirim password ke frontend
                    const token = jwt.sign({ id: adminData.id, username: adminData.username }, KEY_NODEJS, { expiresIn: '1d' });
                    res.status(200).json({ status: 'sukses', pesan: 'Login Berhasil!', dataAdmin: adminData, token: token });
                } else {
                    res.status(401).json({ status: 'gagal', pesan: 'Username atau Password salah!' });
                }
            } catch (error) {
                console.error('Error saat verifikasi password login:', error);
                res.status(500).json({ status: 'error', pesan: 'Terjadi kesalahan saat verifikasi password' });
            }
        } else {
            res.status(401).json({ status: 'gagal', pesan: 'Username atau Password salah!' });
        }
    });
});

app.get('/petugas', cekToken, (req, res) => {
    db.query("SELECT * FROM data_petugas ORDER BY id DESC", (err, results) => {
        if (err) return res.status(500).json({ status: "gagal", pesan: err.message });
        res.json(results);
    });
});

app.post('/petugas', cekToken, upload.single('file_sk'), [
    body('nama_petugas').trim().escape()
], cekValidasi, antiDoubleSubmit, (req, res) => {
    const { nama_petugas, kategori_petugas = null, wilayah = null, no_sk = null } = req.body;
    const file_sk = req.file ? req.file.filename : null;
    if (!file_sk) return res.status(400).json({ status: "gagal", pesan: "File SK wajib diunggah!" });

    const sql = "INSERT INTO data_petugas (nama_petugas, kategori_petugas, wilayah, no_sk, file_sk) VALUES (?, ?, ?, ?, ?)";
    db.query(sql, [nama_petugas, kategori_petugas, wilayah, no_sk, file_sk], (err, result) => {
        if (err) return res.status(500).json({ status: "gagal", pesan: err.message });
        res.json({ status: "sukses", pesan: "Data Petugas disimpan!" });
    });
});

app.put('/petugas/:id', cekToken, upload.single('file_sk'), [
    body('nama_petugas').optional({ checkFalsy: true }).trim().escape()
], cekValidasi, (req, res) => {
    const idPetugas = req.params.id;
    const { nama_petugas, kategori_petugas = null, wilayah = null, no_sk = null, status = 'Aktif' } = req.body;
    const file_sk = req.file ? req.file.filename : null;

    if (file_sk) {
        // Ambil file lama untuk dibersihkan jika ada
        db.query("SELECT file_sk FROM data_petugas WHERE id = ?", [idPetugas], (errOld, oldRows) => {
            const oldFile = oldRows && oldRows[0] ? oldRows[0].file_sk : null;
            hapusFileLokal(oldFile);

            const sql = "UPDATE data_petugas SET nama_petugas = ?, kategori_petugas = ?, wilayah = ?, no_sk = ?, status = COALESCE(?, status), file_sk = ? WHERE id = ?";
            db.query(sql, [nama_petugas, kategori_petugas, wilayah, no_sk, status, file_sk, idPetugas], (err, result) => {
                if (err) return res.status(500).json({ status: "error", pesan: "Gagal memperbarui data petugas." });
                res.json({ status: "sukses", pesan: "Data Petugas beserta SK berhasil diperbarui!" });
            });
        });
    } else {
        const sql = "UPDATE data_petugas SET nama_petugas = ?, kategori_petugas = ?, wilayah = ?, no_sk = ?, status = COALESCE(?, status) WHERE id = ?";
        db.query(sql, [nama_petugas, kategori_petugas, wilayah, no_sk, status, idPetugas], (err, result) => {
            if (err) return res.status(500).json({ status: "error", pesan: "Gagal memperbarui data petugas." });
            res.json({ status: "sukses", pesan: "Data Petugas berhasil diperbarui!" });
        });
    }
});

app.put('/petugas/:id/status', cekToken, (req, res) => {
    const idPetugas = req.params.id;
    const { status } = req.body;
    if (!status) return res.status(400).json({ status: "gagal", pesan: "Status wajib disertakan." });

    const sql = "UPDATE data_petugas SET status = ? WHERE id = ?";
    db.query(sql, [status, idPetugas], (err, result) => {
        if (err) return res.status(500).json({ status: "error", pesan: "Gagal memperbarui status petugas." });
        res.json({ status: "sukses", pesan: `Status petugas berhasil diubah menjadi ${status}!` });
    });
});

app.delete('/petugas/:id', cekToken, (req, res) => {
    const idPetugas = req.params.id;

    // Periksa apakah petugas masih memiliki riwayat kegiatan (Gober atau Sampah)
    const cekSql = `
        SELECT 
            (SELECT COUNT(*) FROM kegiatan_gober WHERE petugas_id = ?) AS jml_gober,
            (SELECT COUNT(*) FROM kegiatan_sampah WHERE petugas_id = ?) AS jml_sampah
    `;
    db.query(cekSql, [idPetugas, idPetugas], (errCek, hasilCek) => {
        if (errCek) return res.status(500).json({ status: "error", pesan: "Gagal memeriksa data riwayat petugas." });

        const totalRiwayat = (hasilCek[0]?.jml_gober || 0) + (hasilCek[0]?.jml_sampah || 0);
        if (totalRiwayat > 0) {
            return res.status(400).json({ 
                status: "gagal", 
                bisaNonaktif: true,
                totalRiwayat: totalRiwayat,
                pesan: `Petugas ini memiliki ${totalRiwayat} riwayat kegiatan harian. Anda dapat menonaktifkan status petugas ini agar tidak muncul lagi pada pengisian laporan baru tanpa menghilangkan riwayat kerjanya.` 
            });
        }

        db.query("SELECT file_sk FROM data_petugas WHERE id = ?", [idPetugas], (errSelect, rows) => {
            const fileSk = rows && rows[0] ? rows[0].file_sk : null;

            const sql = "DELETE FROM data_petugas WHERE id = ?";
            db.query(sql, [idPetugas], (err, result) => {
                if (err) return res.status(500).json({ status: "error", pesan: "Gagal menghapus data petugas." });
                hapusFileLokal(fileSk);
                res.json({ status: "sukses", pesan: "Data Petugas berhasil dihapus!" });
            });
        });
    });
});

app.post('/kegiatan-gober', cekToken, upload.single('foto'), antiDoubleSubmit, (req, res) => {
    const { petugas_id = null, lokasi = null, panjang_meter = null } = req.body;
    const foto = req.file ? req.file.filename : null;
    if (!foto) return res.status(400).json({ status: "gagal", pesan: "Wajib melampirkan foto!" });

    // Sanitasi panjang_meter agar aman jika user mengirimkan teks seperti "30m" atau "30 meter"
    let cleanedPanjang = 0;
    if (panjang_meter !== null && panjang_meter !== undefined) {
        const parsed = parseInt(String(panjang_meter).replace(/[^0-9]/g, ''), 10);
        cleanedPanjang = isNaN(parsed) ? 0 : parsed;
    }

    const sql = "INSERT INTO kegiatan_gober (petugas_id, lokasi, panjang_meter, foto) VALUES (?, ?, ?, ?)";
    db.query(sql, [petugas_id, lokasi, cleanedPanjang, foto], (err, result) => {
        if (err) return res.status(500).json({ status: "error", pesan: err.message });
        res.json({ status: "sukses", pesan: "Laporan Gober disimpan!" });
    });
});

app.get('/kegiatan-gober', cekToken, (req, res) => {
    const sql = `
        SELECT kegiatan_gober.*, data_petugas.nama_petugas 
        FROM kegiatan_gober 
        JOIN data_petugas ON kegiatan_gober.petugas_id = data_petugas.id 
        ORDER BY kegiatan_gober.tanggal_kegiatan DESC
    `;
    db.query(sql, (err, results) => {
        if (err) return res.status(500).json({ status: "error", pesan: err.message });
        res.json(results);
    });
});

app.put('/kegiatan-gober/:id', cekToken, upload.single('foto'), (req, res) => {
    const idKegiatan = req.params.id;
    const { petugas_id = null, lokasi = null, panjang_meter = null } = req.body;
    const foto = req.file ? req.file.filename : null;

    let cleanedPanjang = 0;
    if (panjang_meter !== null && panjang_meter !== undefined) {
        const parsed = parseInt(String(panjang_meter).replace(/[^0-9]/g, ''), 10);
        cleanedPanjang = isNaN(parsed) ? 0 : parsed;
    }

    if (foto) {
        db.query("SELECT foto FROM kegiatan_gober WHERE id = ?", [idKegiatan], (errOld, oldRows) => {
            const oldFoto = oldRows && oldRows[0] ? oldRows[0].foto : null;
            hapusFileLokal(oldFoto);

            const sql = "UPDATE kegiatan_gober SET petugas_id = COALESCE(?, petugas_id), lokasi = COALESCE(?, lokasi), panjang_meter = ?, foto = ? WHERE id = ?";
            db.query(sql, [petugas_id, lokasi, cleanedPanjang, foto, idKegiatan], (err, result) => {
                if (err) return res.status(500).json({ status: "error", pesan: "Gagal memperbarui kegiatan Gober." });
                res.json({ status: "sukses", pesan: "Laporan kegiatan Gober dan bukti foto berhasil diperbarui!" });
            });
        });
    } else {
        const sql = "UPDATE kegiatan_gober SET petugas_id = COALESCE(?, petugas_id), lokasi = COALESCE(?, lokasi), panjang_meter = ? WHERE id = ?";
        db.query(sql, [petugas_id, lokasi, cleanedPanjang, idKegiatan], (err, result) => {
            if (err) return res.status(500).json({ status: "error", pesan: "Gagal memperbarui kegiatan Gober." });
            res.json({ status: "sukses", pesan: "Laporan kegiatan Gober berhasil diperbarui!" });
        });
    }
});

app.delete('/kegiatan-gober/:id', cekToken, (req, res) => {
    const idKegiatan = req.params.id;
    db.query("SELECT foto FROM kegiatan_gober WHERE id = ?", [idKegiatan], (errSelect, rows) => {
        const foto = rows && rows[0] ? rows[0].foto : null;
        const sql = "DELETE FROM kegiatan_gober WHERE id = ?";
        db.query(sql, [idKegiatan], (err, result) => {
            if (err) return res.status(500).json({ status: "error", pesan: "Gagal menghapus kegiatan Gober." });
            hapusFileLokal(foto);
            res.json({ status: "sukses", pesan: "Laporan kegiatan Gober berhasil dihapus!" });
        });
    });
});

app.post('/kegiatan-sampah', cekToken, upload.single('foto'), antiDoubleSubmit, (req, res) => {
    const { petugas_id = null, kategori_tugas = null, data_rw = null, berat_kiloan = null } = req.body;
    const foto = req.file ? req.file.filename : null;
    
    if (!foto) return res.status(400).json({ status: "gagal", pesan: "Wajib melampirkan foto timbangan!" });

    const cleanedBerat = parseFloat(String(berat_kiloan).replace(',', '.')) || 0;

    const sql = "INSERT INTO kegiatan_sampah (petugas_id, kategori_tugas, data_rw, berat_kiloan, foto) VALUES (?, ?, ?, ?, ?)";
    db.query(sql, [petugas_id, kategori_tugas, data_rw, cleanedBerat, foto], (err, result) => {
        if (err) return res.status(500).json({ status: "error", pesan: err.message });
        res.json({ status: "sukses", pesan: `Laporan ${kategori_tugas} beserta foto disimpan!` });
    });
});

app.get('/kegiatan-sampah', cekToken, (req, res) => {
    const sql = `
        SELECT kegiatan_sampah.*, data_petugas.nama_petugas 
        FROM kegiatan_sampah 
        JOIN data_petugas ON kegiatan_sampah.petugas_id = data_petugas.id 
        ORDER BY kegiatan_sampah.tanggal_kegiatan DESC
    `;
    db.query(sql, (err, results) => {
        if (err) return res.status(500).json({ status: "error", pesan: err.message });
        res.json(results);
    });
});

app.put('/kegiatan-sampah/:id', cekToken, upload.single('foto'), (req, res) => {
    const idKegiatan = req.params.id;
    const { petugas_id = null, kategori_tugas = null, data_rw = null, berat_kiloan = null } = req.body;
    const foto = req.file ? req.file.filename : null;

    const cleanedBerat = parseFloat(String(berat_kiloan).replace(',', '.')) || 0;

    if (foto) {
        db.query("SELECT foto FROM kegiatan_sampah WHERE id = ?", [idKegiatan], (errOld, oldRows) => {
            const oldFoto = oldRows && oldRows[0] ? oldRows[0].foto : null;
            hapusFileLokal(oldFoto);

            const sql = "UPDATE kegiatan_sampah SET petugas_id = COALESCE(?, petugas_id), kategori_tugas = COALESCE(?, kategori_tugas), data_rw = COALESCE(?, data_rw), berat_kiloan = ?, foto = ? WHERE id = ?";
            db.query(sql, [petugas_id, kategori_tugas, data_rw, cleanedBerat, foto, idKegiatan], (err, result) => {
                if (err) return res.status(500).json({ status: "error", pesan: "Gagal memperbarui kegiatan Sampah." });
                res.json({ status: "sukses", pesan: "Laporan kegiatan Sampah dan bukti timbangan berhasil diperbarui!" });
            });
        });
    } else {
        const sql = "UPDATE kegiatan_sampah SET petugas_id = COALESCE(?, petugas_id), kategori_tugas = COALESCE(?, kategori_tugas), data_rw = COALESCE(?, data_rw), berat_kiloan = ? WHERE id = ?";
        db.query(sql, [petugas_id, kategori_tugas, data_rw, cleanedBerat, idKegiatan], (err, result) => {
            if (err) return res.status(500).json({ status: "error", pesan: "Gagal memperbarui kegiatan Sampah." });
            res.json({ status: "sukses", pesan: "Laporan kegiatan Sampah berhasil diperbarui!" });
        });
    }
});

app.delete('/kegiatan-sampah/:id', cekToken, (req, res) => {
    const idKegiatan = req.params.id;
    db.query("SELECT foto FROM kegiatan_sampah WHERE id = ?", [idKegiatan], (errSelect, rows) => {
        const foto = rows && rows[0] ? rows[0].foto : null;
        const sql = "DELETE FROM kegiatan_sampah WHERE id = ?";
        db.query(sql, [idKegiatan], (err, result) => {
            if (err) return res.status(500).json({ status: "error", pesan: "Gagal menghapus kegiatan Sampah." });
            hapusFileLokal(foto);
            res.json({ status: "sukses", pesan: "Laporan kegiatan Sampah berhasil dihapus!" });
        });
    });
});

app.post('/kegiatan-agenda', cekToken, upload.single('foto_dokumentasi'), antiDoubleSubmit, (req, res) => {
    const { judul_agenda = null, kategori_agenda = null, tanggal_waktu = null, waktu_selesai = null, lokasi = null, catatan_reminder = null } = req.body;
    const foto_dokumentasi = req.file ? req.file.filename : null;

    const formatDateTime = (val) => (val && typeof val === 'string' && val.trim() !== '') ? val.replace('T', ' ') : null;
    const cleanedTanggalWaktu = formatDateTime(tanggal_waktu);
    const cleanedSelesai = formatDateTime(waktu_selesai);

    const sql = `INSERT INTO kegiatan_agenda (judul_agenda, kategori_agenda, tanggal_waktu, waktu_selesai, lokasi, catatan_reminder, foto_dokumentasi) VALUES (?, ?, ?, ?, ?, ?, ?)`;
    db.query(sql, [judul_agenda, kategori_agenda, cleanedTanggalWaktu, cleanedSelesai, lokasi, catatan_reminder, foto_dokumentasi], (err, result) => {
        if (err) return res.status(500).json({ status: "error", pesan: err.message });
        res.json({ status: "sukses", pesan: "Agenda berhasil dijadwalkan!" });
    });
});

app.get('/kegiatan-agenda', cekToken, (req, res) => {
    db.query("SELECT * FROM kegiatan_agenda ORDER BY tanggal_waktu ASC", (err, results) => {
        if (err) return res.status(500).json({ status: "error", pesan: err.message });
        res.json(results);
    });
});

app.delete('/kegiatan-agenda/:id', cekToken, (req, res) => {
    const idAgenda = req.params.id; 
    db.query("SELECT foto_dokumentasi FROM kegiatan_agenda WHERE id = ?", [idAgenda], (errSelect, rows) => {
        const foto = rows && rows[0] ? rows[0].foto_dokumentasi : null;
        const sql = "DELETE FROM kegiatan_agenda WHERE id = ?"; 
        db.query(sql, [idAgenda], (err, result) => {
            if (err) return res.status(500).json({ status: "error", pesan: "Gagal menghapus agenda." });
            hapusFileLokal(foto);
            res.json({ status: "sukses", pesan: "Agenda berhasil dibatalkan dan dihapus dari jadwal!" });
        });
    });
});

app.put('/kegiatan-agenda/:id', cekToken, upload.single('foto_dokumentasi'), (req, res) => {
    const idAgenda = req.params.id;
    const { judul_agenda = null, kategori_agenda = null, tanggal_waktu = null, waktu_selesai = null, lokasi = null, catatan_reminder = null } = req.body;
    const foto = req.file ? req.file.filename : null;

    const formatDateTime = (val) => (val && typeof val === 'string' && val.trim() !== '') ? val.replace('T', ' ') : null;
    const cleanedTanggalWaktu = formatDateTime(tanggal_waktu);
    const cleanedSelesai = formatDateTime(waktu_selesai);

    if (foto) {
        db.query("SELECT foto_dokumentasi FROM kegiatan_agenda WHERE id = ?", [idAgenda], (errOld, oldRows) => {
            const oldFoto = oldRows && oldRows[0] ? oldRows[0].foto_dokumentasi : null;
            hapusFileLokal(oldFoto);

            const sql = `UPDATE kegiatan_agenda SET judul_agenda = COALESCE(?, judul_agenda), kategori_agenda = COALESCE(?, kategori_agenda), tanggal_waktu = COALESCE(?, tanggal_waktu), waktu_selesai = ?, lokasi = COALESCE(?, lokasi), catatan_reminder = ?, foto_dokumentasi = ? WHERE id = ?`;
            db.query(sql, [judul_agenda, kategori_agenda, cleanedTanggalWaktu, cleanedSelesai, lokasi, catatan_reminder, foto, idAgenda], (err, result) => {
                if (err) return res.status(500).json({ status: "error", pesan: "Gagal memperbarui agenda." });
                res.json({ status: "sukses", pesan: "Agenda dan foto dokumentasi berhasil diperbarui!" });
            });
        });
    } else {
        const sql = `UPDATE kegiatan_agenda SET judul_agenda = COALESCE(?, judul_agenda), kategori_agenda = COALESCE(?, kategori_agenda), tanggal_waktu = COALESCE(?, tanggal_waktu), waktu_selesai = ?, lokasi = COALESCE(?, lokasi), catatan_reminder = ? WHERE id = ?`;
        db.query(sql, [judul_agenda, kategori_agenda, cleanedTanggalWaktu, cleanedSelesai, lokasi, catatan_reminder, idAgenda], (err, result) => {
            if (err) return res.status(500).json({ status: "error", pesan: "Gagal memperbarui agenda." });
            res.json({ status: "sukses", pesan: "Agenda kegiatan berhasil diperbarui!" });
        });
    }
});

app.put('/kegiatan-agenda/:id/foto', cekToken, upload.single('foto_dokumentasi'), (req, res) => {
    const foto = req.file ? req.file.filename : null;
    if (!foto) return res.status(400).json({ status: "gagal", pesan: "File foto tidak ditemukan!" });

    db.query("SELECT foto_dokumentasi FROM kegiatan_agenda WHERE id = ?", [req.params.id], (errOld, oldRows) => {
        const oldFoto = oldRows && oldRows[0] ? oldRows[0].foto_dokumentasi : null;
        hapusFileLokal(oldFoto);

        const sql = "UPDATE kegiatan_agenda SET foto_dokumentasi = ? WHERE id = ?";
        db.query(sql, [foto, req.params.id], (err, result) => {
            if (err) return res.status(500).json({ status: "error", pesan: err.message });
            res.json({ status: "sukses", pesan: "Foto dokumentasi disusulkan." });
        });
    });
});

app.get('/peta-gis', cekToken, (req, res) => {
    db.query("SELECT * FROM titik_peta_gis", (err, results) => {
        if (err) return res.status(500).json({ status: "error", pesan: err.message });
        res.json(results);
    });
});

app.post('/peta-gis', cekToken, upload.single('foto_url'), [
    body('nama_lokasi').trim(),
    body('alamat').trim()
], cekValidasi, antiDoubleSubmit, (req, res) => {
    const { kategori_lokasi = null, nama_lokasi = null, alamat = null, latitude = null, longitude = null, status = null, ketua = null, luas_lahan = null, data_rw = null } = req.body;
    const foto = req.file ? req.file.filename : null;

    const sql = `INSERT INTO titik_peta_gis (kategori_lokasi, nama_lokasi, alamat, latitude, longitude, foto_url, status, ketua, luas_lahan, data_rw) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`;
    const values = [kategori_lokasi, nama_lokasi, alamat, latitude, longitude, foto, status || null, ketua || null, luas_lahan || null, data_rw || null];

    db.query(sql, values, (err, result) => {
        if (err) return res.status(500).json({ status: "error", pesan: err.message });
        res.json({ status: "sukses", pesan: "Titik lokasi ditanam di peta!" });
    });
});

app.put('/peta-gis/:id', cekToken, upload.single('foto_url'), [
    body('nama_lokasi').optional().trim(),
    body('alamat').optional().trim()
], cekValidasi, (req, res) => {
    const idTitik = req.params.id;
    const { kategori_lokasi = null, nama_lokasi = null, alamat = null, latitude = null, longitude = null, status = null, ketua = null, luas_lahan = null, data_rw = null } = req.body;
    const foto = req.file ? req.file.filename : null;

    if (foto) {
        db.query("SELECT foto_url FROM titik_peta_gis WHERE id = ?", [idTitik], (errOld, oldRows) => {
            const oldFoto = oldRows && oldRows[0] ? oldRows[0].foto_url : null;
            hapusFileLokal(oldFoto);

            const sql = `UPDATE titik_peta_gis SET kategori_lokasi = COALESCE(?, kategori_lokasi), nama_lokasi = COALESCE(?, nama_lokasi), alamat = COALESCE(?, alamat), latitude = COALESCE(?, latitude), longitude = COALESCE(?, longitude), status = ?, ketua = ?, luas_lahan = ?, data_rw = ?, foto_url = ? WHERE id = ?`;
            db.query(sql, [kategori_lokasi, nama_lokasi, alamat, latitude, longitude, status || null, ketua || null, luas_lahan || null, data_rw || null, foto, idTitik], (err, result) => {
                if (err) return res.status(500).json({ status: "error", pesan: "Gagal memperbarui titik peta." });
                res.json({ status: "sukses", pesan: "Data titik peta dan foto lokasi berhasil diperbarui!" });
            });
        });
    } else {
        const sql = `UPDATE titik_peta_gis SET kategori_lokasi = COALESCE(?, kategori_lokasi), nama_lokasi = COALESCE(?, nama_lokasi), alamat = COALESCE(?, alamat), latitude = COALESCE(?, latitude), longitude = COALESCE(?, longitude), status = ?, ketua = ?, luas_lahan = ?, data_rw = ? WHERE id = ?`;
        db.query(sql, [kategori_lokasi, nama_lokasi, alamat, latitude, longitude, status || null, ketua || null, luas_lahan || null, data_rw || null, idTitik], (err, result) => {
            if (err) return res.status(500).json({ status: "error", pesan: "Gagal memperbarui titik peta." });
            res.json({ status: "sukses", pesan: "Data titik peta berhasil diperbarui!" });
        });
    }
});

app.put('/peta-gis/:id/status', cekToken, (req, res) => {
    const sql = "UPDATE titik_peta_gis SET status = ? WHERE id = ?";
    db.query(sql, [req.body.status, req.params.id], (err, result) => {
        if (err) return res.status(500).json({ status: "error", pesan: err.message });
        res.json({ status: "sukses", pesan: "Status lokasi berhasil diperbarui!" });
    });
});

app.delete('/peta-gis/:id', cekToken, (req, res) => {
    const idTitikPeta = req.params.id; 
    db.query("SELECT foto_url FROM titik_peta_gis WHERE id = ?", [idTitikPeta], (errSelect, rows) => {
        const foto = rows && rows[0] ? rows[0].foto_url : null;
        const sql = "DELETE FROM titik_peta_gis WHERE id = ?"; 
        db.query(sql, [idTitikPeta], (err, result) => {
            if (err) return res.status(500).json({ status: "error", pesan: "Gagal menghapus titik pada peta GIS." });
            hapusFileLokal(foto);
            res.json({ status: "sukses", pesan: "Titik peta berhasil dihapus!" });
        });
    });
});

app.post('/lupa-password', [
    body('username').trim().escape().notEmpty().withMessage('Username tidak boleh kosong!')
], cekValidasi, antiDoubleSubmit, (req, res) => {
    const { username } = req.body;

    // Pastikan username memang terdaftar di tabel admin agar tidak terjadi spam
    db.query('SELECT id FROM admin WHERE username = ?', [username], (errCek, hasilCek) => {
        if (errCek) return res.status(500).json({ status: "error", pesan: "Gagal memeriksa data pengguna." });
        if (hasilCek.length === 0) {
            return res.status(404).json({ status: "gagal", pesan: `Username '${username}' tidak terdaftar sebagai staf admin.` });
        }

        const pesan = `Staf dengan username '${username}' meminta reset password.`;
        const sql = `INSERT INTO notifikasi_sistem (username_staf, pesan) VALUES (?, ?)`;
        db.query(sql, [username, pesan], (err, result) => {
            if (err) return res.status(500).json({ status: "error", pesan: "Gagal mengirim permintaan reset password." });
            res.json({ status: "sukses", pesan: "Permintaan reset password berhasil dikirim ke Master Admin." });
        });
    });
});

app.get('/notifikasi', cekToken, (req, res) => {
    const sql = `SELECT * FROM notifikasi_sistem WHERE status = 'Belum Dibaca' ORDER BY tanggal DESC`;
    db.query(sql, (err, results) => {
        if (err) return res.status(500).json({ status: "error", pesan: "Gagal menarik data notifikasi." });
        res.json({ status: "sukses", data: results });
    });
});

app.put('/notifikasi/:id', cekToken, (req, res) => {
    const idNotif = req.params.id;
    const sql = `UPDATE notifikasi_sistem SET status = 'Sudah Dibaca' WHERE id = ?`;
    db.query(sql, [idNotif], (err, result) => {
        if (err) return res.status(500).json({ status: "error", pesan: "Gagal memperbarui status notifikasi." });
        res.json({ status: "sukses", pesan: "Pesan telah ditandai selesai dibaca." });
    });
});

app.use((err, req, res, next) => {
    if (err instanceof multer.MulterError) {
        if (err.code === 'LIMIT_FILE_SIZE') {
            return res.status(400).json({ status: 'gagal', pesan: 'Ukuran file terlalu besar! Maksimal 5 MB.' });
        }
        return res.status(400).json({ status: 'gagal', pesan: `Galat unggah file: ${err.message}` });
    }
    if (err && err.message && err.message.includes('Format file tidak didukung')) {
        return res.status(400).json({ status: 'gagal', pesan: err.message });
    }
    console.error("Error tak terduga:", err);
    res.status(500).json({ status: 'error', pesan: 'Kesalahan sistem saat memproses permintaan.' });
});

const PORT = process.env.PORT || 5000;
app.listen(PORT, '0.0.0.0', () => {
    console.log(`Server digembok dan berjalan aman di port ${PORT}`);
});