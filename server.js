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
const KEY_NODEJS = process.env.KEY_NODE_JS;

const cloudinary = require('cloudinary').v2;
const { CloudinaryStorage } = require('multer-storage-cloudinary');

// Menghubungkan ke brankas Cloudinary menggunakan kunci di .env
cloudinary.config({
  cloud_name: process.env.CLOUDINARY_CLOUD_NAME,
  api_key: process.env.CLOUDINARY_API_KEY,
  api_secret: process.env.CLOUDINARY_API_SECRET
});

// Instruksi baru untuk Multer (Satpam) agar menitipkan ke Kurir
const storage = new CloudinaryStorage({
  cloudinary: cloudinary,
  params: {
    folder: 'one_ekbang',
    allowed_formats: ['jpg', 'png', 'jpeg', 'pdf', 'webp']
  },
});

const upload = multer({ 
    storage: storage,
    limits: { fileSize: 5 * 1024 * 1024 }
});

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
    host: 'mysql-379152c5-one-ekbang.d.aivencloud.com',
    port: 27863,
    user: 'avnadmin',
    password: process.env.DB_PASSWORD, 
    database: 'defaultdb',
    ssl: {
        rejectUnauthorized: false 
    },
    waitForConnections: true,
    connectionLimit: 10,
    queueLimit: 0
});

db.getConnection((err, conn) => {
    if (err) {
        console.log('Waduh, gagal masuk gudang:', err.message);
    } else {
        console.log('DATABASE MYSQL aman terkoneksi! 🗄️');
        conn.release(); 
    }
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

// === TARGET 2: MESIN X-RAY (MIDDLEWARE VALIDASI INPUT) ===
const cekValidasi = (req, res, next) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        // Hapus file yang terlanjur terupload ke Cloudinary jika validasi teks gagal
        if (req.file && req.file.filename) {
            cloudinary.uploader.destroy(req.file.filename).catch(err => console.log('Gagal hapus cloudinary:', err));
        }
        if (req.files) {
            Object.values(req.files).flat().forEach(f => {
                if (f.filename) cloudinary.uploader.destroy(f.filename).catch(err => console.log('Gagal hapus cloudinary:', err));
            });
        }
        return res.status(400).json({ status: "gagal", pesan: errors.array()[0].msg });
    }
    next();
};

app.get('/', (req, res) => {
    res.send('API Backend Ekbang Berjalan Normal! 🚀');
});

app.get('/admin', cekToken, (req,res) => {
    const usersSQL = 'SELECT id, nik, nama_lengkap, username FROM admin';
    db.query(usersSQL, (err,hasil) => {
        if(err) return res.send('Gagal mengambil data users dari Mysql!');
        res.json(hasil);
    })
});

// Rute POST Admin (DIGEMBOK & DIVALIDASI KETAT)
// === TAMBAHAN BCRYPT: Mengubah callback menjadi async ===
app.post('/admin', cekToken, [
    body('nik').isNumeric().withMessage('NIK wajib berupa angka!').isLength({ min: 16, max: 16 }).withMessage('NIK harus persis 16 digit!'),
    body('nama_lengkap').trim().escape().notEmpty().withMessage('Nama lengkap wajib diisi!'),
    body('username').trim().escape().notEmpty(),
    body('password').notEmpty()
], cekValidasi, async (req, res) => {
    const { nik, nama_lengkap, username, password } = req.body;
    
    try {
        // === TAMBAHAN BCRYPT: Mengacak password sebelum disimpan ===
        const saltRounds = 10;
        const hashedPassword = await bcrypt.hash(password, saltRounds);
        
        const sql = `INSERT INTO admin (nik, nama_lengkap, username, password) VALUES (?, ?, ?, ?)`;
        // === TAMBAHAN BCRYPT: Kirim hashedPassword, BUKAN password asli ===
        db.query(sql, [nik, nama_lengkap, username, hashedPassword], (err, result) => {
            if (err) return res.status(500).json({ status: "error", pesan: "Gagal membuat akun." });
            res.json({ status: "sukses", pesan: "Akun staf baru berhasil dibuat!" });
        });
    } catch (error) {
        return res.status(500).json({ status: "error", pesan: "Gagal mengamankan password." });
    }
});

app.delete('/admin/:id', cekToken, (req, res) => {
    const idAdmin = req.params.id;
    const sql = "DELETE FROM admin WHERE id = ?";
    db.query(sql, [idAdmin], (err, result) => {
        if (err) return res.status(500).json({ status: "error", pesan: "Gagal menghapus akun." });
        res.json({ status: "sukses", pesan: "Akses akun staf berhasil dicabut secara permanen!" });
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
    body('nik').isNumeric().withMessage('NIK wajib berupa angka!'),
    body('nama').trim().escape()
], cekValidasi, (req, res) => {
    const { nik, nama, no_telepon = null, jenisLayanan = null } = req.body;
    const getNamaFile = (namaField) => req.files && req.files[namaField] ? req.files[namaField][0].path : null;

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
        if(err) return res.status(500).send('Gagal menyimpan data baru ke database!');
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

app.put('/layanan/:id', cekToken, (req, res) => {
    const sql = `UPDATE pengajuan_layanan SET status = ? WHERE id = ?`;
    db.query(sql, [req.body.status, req.params.id], (err, hasil) => {
        if (err) return res.status(500).json({ status: 'error', pesan: 'Gagal memperbarui status.' });
        res.status(200).json({ status: 'sukses', pesan: `Status diperbarui!` });
    });
});

// RUTE POST LOGIN (TERBUKA UTK PUBLIK + MENCETAK TOKEN)
app.post('/login', [
    body('username').trim().escape(),
    body('password').trim().escape()
], cekValidasi, (req, res) => {
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
                if (adminData.password && (adminData.password.startsWith('$2a$') || adminData.password.startsWith('$2b$'))) {
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
                    delete adminData.password; // Jangan kirim password ke frontend
                    const token = jwt.sign({ id: adminData.id, username: adminData.username }, KEY_NODEJS, { expiresIn: '1d' });
                    res.status(200).json({ status: 'sukses', pesan: 'Login Berhasil!', dataAdmin: adminData, token: token });
                } else {
                    res.status(401).json({ status: 'gagal', pesan: 'Username atau Password salah!' });
                }
            } catch (error) {
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
], cekValidasi, (req, res) => {
    const { nama_petugas, kategori_petugas = null, wilayah = null, no_sk = null } = req.body;
    const file_sk = req.file ? req.file.path : null;
    if (!file_sk) return res.status(400).json({ status: "gagal", pesan: "File SK wajib diunggah!" });

    const sql = "INSERT INTO data_petugas (nama_petugas, kategori_petugas, wilayah, no_sk, file_sk) VALUES (?, ?, ?, ?, ?)";
    db.query(sql, [nama_petugas, kategori_petugas, wilayah, no_sk, file_sk], (err, result) => {
        if (err) return res.status(500).json({ status: "gagal", pesan: err.message });
        res.json({ status: "sukses", pesan: "Data Petugas disimpan!" });
    });
});

app.post('/kegiatan-gober', cekToken, upload.single('foto'), (req, res) => {
    const { petugas_id = null, lokasi = null, panjang_meter = null } = req.body;
    const foto = req.file ? req.file.path : null;
    if (!foto) return res.status(400).json({ status: "gagal", pesan: "Wajib melampirkan foto!" });

    const sql = "INSERT INTO kegiatan_gober (petugas_id, lokasi, panjang_meter, foto) VALUES (?, ?, ?, ?)";
    db.query(sql, [petugas_id, lokasi, panjang_meter, foto], (err, result) => {
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

app.post('/kegiatan-sampah', cekToken, upload.single('foto'), (req, res) => {
    const { petugas_id = null, kategori_tugas = null, data_rw = null, berat_kiloan = null } = req.body;
    const foto = req.file ? req.file.path : null;
    
    if (!foto) return res.status(400).json({ status: "gagal", pesan: "Wajib melampirkan foto timbangan!" });

    const sql = "INSERT INTO kegiatan_sampah (petugas_id, kategori_tugas, data_rw, berat_kiloan, foto) VALUES (?, ?, ?, ?, ?)";
    db.query(sql, [petugas_id, kategori_tugas, data_rw, berat_kiloan, foto], (err, result) => {
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

app.post('/kegiatan-agenda', cekToken, upload.single('foto_dokumentasi'), (req, res) => {
    const { judul_agenda = null, kategori_agenda = null, tanggal_waktu = null, lokasi = null, catatan_reminder = null } = req.body;
    const foto_dokumentasi = req.file ? req.file.path : null;

    const sql = `INSERT INTO kegiatan_agenda (judul_agenda, kategori_agenda, tanggal_waktu, lokasi, catatan_reminder, foto_dokumentasi) VALUES (?, ?, ?, ?, ?, ?)`;
    db.query(sql, [judul_agenda, kategori_agenda, tanggal_waktu, lokasi, catatan_reminder, foto_dokumentasi], (err, result) => {
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
    const sql = "DELETE FROM kegiatan_agenda WHERE id = ?"; 
    
    db.query(sql, [idAgenda], (err, result) => {
        if (err) return res.status(500).json({ status: "error", pesan: "Gagal menghapus agenda." });
        res.json({ status: "sukses", pesan: "Agenda berhasil dibatalkan dan dihapus dari jadwal!" });
    });
});

app.put('/kegiatan-agenda/:id/foto', cekToken, upload.single('foto_dokumentasi'), (req, res) => {
    const foto = req.file ? req.file.path : null;
    if (!foto) return res.status(400).json({ status: "gagal", pesan: "File foto tidak ditemukan!" });

    const sql = "UPDATE kegiatan_agenda SET foto_dokumentasi = ? WHERE id = ?";
    db.query(sql, [foto, req.params.id], (err, result) => {
        if (err) return res.status(500).json({ status: "error", pesan: err.message });
        res.json({ status: "sukses", pesan: "Foto dokumentasi disusulkan." });
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
], cekValidasi, (req, res) => {
    const { kategori_lokasi = null, nama_lokasi = null, alamat = null, latitude = null, longitude = null, status = null, ketua = null, luas_lahan = null, data_rw = null } = req.body;
    const foto = req.file ? req.file.path : null;

    const sql = `INSERT INTO titik_peta_gis (kategori_lokasi, nama_lokasi, alamat, latitude, longitude, foto_url, status, ketua, luas_lahan, data_rw) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`;
    const values = [kategori_lokasi, nama_lokasi, alamat, latitude, longitude, foto, status || null, ketua || null, luas_lahan || null, data_rw || null];

    db.query(sql, values, (err, result) => {
        if (err) return res.status(500).json({ status: "error", pesan: err.message });
        res.json({ status: "sukses", pesan: "Titik lokasi ditanam di peta!" });
    });
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
    const sql = "DELETE FROM titik_peta_gis WHERE id = ?"; 
    
    db.query(sql, [idTitikPeta], (err, result) => {
        if (err) return res.status(500).json({ status: "error", pesan: "Gagal menghapus titik pada peta gis!." });
        res.json({ status: "sukses", pesan: "Titik peta berhasil di hapus!" });
    });
});

app.post('/lupa-password', [
    body('username').trim().escape().notEmpty().withMessage('Username tidak boleh kosong!')
], cekValidasi, (req, res) => {
    const { username } = req.body;
    const pesan = `Staf dengan username '${username}' meminta reset password.`;

    const sql = `INSERT INTO notifikasi_sistem (username_staf, pesan) VALUES (?, ?)`;
    db.query(sql, [username, pesan], (err, result) => {
        if (err) return res.status(500).json({ status: "error", pesan: "Gagal mengirim permintaan." });
        res.json({ status: "sukses", pesan: "Permintaan reset password berhasil dikirim ke Master Admin." });
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
    if (err instanceof multer.MulterError && err.code === 'LIMIT_FILE_SIZE') {
        return res.status(400).json({ status: 'gagal', pesan: 'Maksimal 5 MB ya!' });
    }
    console.error("Error:", err);
    res.status(500).json({ status: 'error', pesan: 'Kesalahan sistem saat memproses.' });
});

const PORT = process.env.PORT || 5000;
app.listen(PORT, '0.0.0.0', () => {
    console.log(`Server digembok dan berjalan aman di port ${PORT}`);
});