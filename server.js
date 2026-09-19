const express = require('express');
const cors = require('cors');
const mysql = require('mysql2'); 
const fs = require('fs');
const path = require('path'); 
const multer = require('multer');
require('dotenv').config();

// --- ALAT KEAMANAN BARU ---
const jwt = require('jsonwebtoken');
const { body, validationResult } = require('express-validator'); 
const KEY_NODEJS = "dataekbang2026"; 

const uploadDir = path.join(__dirname, 'uploads');

if (!fs.existsSync(uploadDir)) {
    fs.mkdirSync(uploadDir, { recursive: true });
}

const storage = multer.diskStorage({
    destination: (req, file, cb) => {
        cb(null, uploadDir); 
    },
    filename: (req, file, cb) => {
        cb(null, Date.now() + '-' + file.originalname);
    }
});

const upload = multer({ 
    storage: storage,
    limits: { fileSize: 5 * 1024 * 1024 }
});

const app = express();

const corsOptions = {
    origin: ['https://frontend-one-ekbang.vercel.app', 'http://localhost:5173'],
    credentials: true
};

app.use(cors(corsOptions));

app.use(express.json()); 

app.use('/uploads', express.static(path.join(__dirname, 'uploads')));

const db = mysql.createConnection({
    host: 'mysql-379152c5-one-ekbang.d.aivencloud.com',
    port: 27863,
    user: 'avnadmin',
    password: process.env.DB_PASSWORD, 
    database: 'defaultdb',
    ssl: {
        rejectUnauthorized: false // Memaksa Node.js menggunakan SSL agar diterima Aiven
    }
});

db.connect((error) => {
    if (error) {
        console.log('Waduh, gagal masuk gudang:', error);
    } else {
        console.log('Gudang MySQL Berhasil Tersambung! 🚀');
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
        return res.status(400).json({ status: "gagal", pesan: errors.array()[0].msg });
    }
    next();
};


// KUMPULAN RUTE API SERVER

// Rute GET Admin (DIGEMBOK)
app.get('/admin', cekToken, (req,res) => {
    const usersSQL = 'SELECT * FROM admin';
    db.query(usersSQL, (err,hasil) => {
        if(err) return res.send('Gagal mengambil data users dari Mysql!');
        res.json(hasil);
    })
});

// Rute POST Admin (DIGEMBOK & DIVALIDASI KETAT)
app.post('/admin', cekToken, [
    body('nik').isNumeric().withMessage('NIK wajib berupa angka!').isLength({ min: 16, max: 16 }).withMessage('NIK harus persis 16 digit!'),
    body('nama_lengkap').trim().escape().notEmpty().withMessage('Nama lengkap wajib diisi!'),
    body('username').trim().escape().notEmpty(),
    body('password').notEmpty()
], cekValidasi, (req, res) => {
    const { nik, nama_lengkap, username, password } = req.body;
    const sql = `INSERT INTO admin (nik, nama_lengkap, username, password) VALUES (?, ?, ?, ?)`;
    db.query(sql, [nik, nama_lengkap, username, password], (err, result) => {
        if (err) return res.status(500).json({ status: "error", pesan: "Gagal membuat akun." });
        res.json({ status: "sukses", pesan: "Akun staf baru berhasil dibuat!" });
    });
});

// Rute DELETE Admin (DIGEMBOK)
app.delete('/admin/:id', cekToken, (req, res) => {
    const idAdmin = req.params.id;
    const sql = "DELETE FROM admin WHERE id = ?";
    db.query(sql, [idAdmin], (err, result) => {
        if (err) return res.status(500).json({ status: "error", pesan: "Gagal menghapus akun." });
        res.json({ status: "sukses", pesan: "Akses akun staf berhasil dicabut secara permanen!" });
    });
});

// Rute POST Layanan (TERBUKA UTK PUBLIK + DIVALIDASI + FOTO HALAMAN)
app.post('/layanan', upload.fields([
    { name: 'foto_ktp', maxCount: 1 }, { name: 'foto_kk', maxCount: 1 }, { name: 'surat_pengantar', maxCount: 1 },
    { name: 'sertifikat_tanah', maxCount: 1 }, { name: 'foto_kondisi_rumah', maxCount: 1 }, { name: 'foto_lokasi', maxCount: 1 },
    { name: 'sk_buruan_sae', maxCount: 1 }, { name: 'kebutuhan_tanaman', maxCount: 1 }, { name: 'dokumen_a1', maxCount: 1 },
    { name: 'dokumen_a2', maxCount: 1 }, { name: 'foto_rembuk', maxCount: 1 }, { name: 'daftar_hadir', maxCount: 1 },
    { name: 'ba_muskel', maxCount: 1 }, { name: 'foto_muskel', maxCount: 1 },
    { name: 'foto_halaman', maxCount: 1 } // <--- ALAT PENERIMA FOTO HALAMAN BARU
]), [
    body('nik').isNumeric().withMessage('NIK wajib berupa angka!'),
    body('nama').trim().escape()
], cekValidasi, (req, res) => {
    const { nik, nama, no_telepon, jenisLayanan } = req.body;
    const getNamaFile = (namaField) => req.files && req.files[namaField] ? req.files[namaField][0].filename : null;

    const dataKirim = [
        nik, nama, no_telepon, jenisLayanan, getNamaFile('foto_ktp'), getNamaFile('foto_kk'), getNamaFile('surat_pengantar'), 
        getNamaFile('sertifikat_tanah'), getNamaFile('foto_kondisi_rumah'), getNamaFile('foto_lokasi'), getNamaFile('sk_buruan_sae'), getNamaFile('kebutuhan_tanaman'), 
        getNamaFile('dokumen_a1'), getNamaFile('dokumen_a2'), getNamaFile('foto_rembuk'), getNamaFile('daftar_hadir'), getNamaFile('ba_muskel'), getNamaFile('foto_muskel'),
        getNamaFile('foto_halaman') // <--- DATA DIMASUKKAN KE ARRAY
    ];

    const tambahLayananSQL = `INSERT INTO pengajuan_layanan 
        (nik_pemohon, nama_pemohon, no_telepon, jenis_layanan, foto_ktp, foto_kk, surat_pengantar, sertifikat_tanah, foto_kondisi_rumah, foto_lokasi, sk_buruan_sae, kebutuhan_tanaman, dokumen_a1, dokumen_a2, foto_rembuk, daftar_hadir, ba_muskel, foto_muskel, foto_halaman) 
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`; 
    
    db.query(tambahLayananSQL, dataKirim, (err, hasil) => {
        if(err) return res.status(500).send('Gagal menyimpan data baru ke database!');
        res.json({ status: 'sukses', pesan: 'Data layanan berhasil ditambahkan!', hasil: hasil });
    });
});

// Rute GET Layanan (DIGEMBOK)
app.get('/layanan', cekToken, (req, res) => {
    const sql = `SELECT * FROM pengajuan_layanan ORDER BY tanggal_pengajuan DESC`;
    db.query(sql, (err, results) => {
        if (err) return res.status(500).json({ status: 'error', pesan: 'Gagal ambil data pengajuan.' });
        res.status(200).json({ status: 'sukses', data: results });
    });
});

// Rute PUT Layanan (DIGEMBOK)
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
    const sql = `SELECT * FROM admin WHERE username = ? AND password = ?`;
    
    db.query(sql, [username, password], (err, hasil) => {
        if (err) return res.status(500).json({ status: 'error', pesan: 'Kesalahan server' });
        
        if (hasil.length > 0) {
            const adminData = hasil[0];
            const token = jwt.sign({ id: adminData.id, username: adminData.username }, KEY_NODEJS, { expiresIn: '1d' });
            res.status(200).json({ status: 'sukses', pesan: 'Login Berhasil!', dataAdmin: adminData, token: token });
        } else {
            res.status(401).json({ status: 'gagal', pesan: 'Username atau Password salah!' });
        }
    });
});

// SISA RUTE LAINNYA (SEMUA DIGEMBOK DENGAN cekToken)
app.get('/petugas', cekToken, (req, res) => {
    db.query("SELECT * FROM data_petugas ORDER BY id DESC", (err, results) => {
        if (err) return res.status(500).json({ status: "gagal", pesan: err.message });
        res.json(results);
    });
});

app.post('/petugas', cekToken, upload.single('file_sk'), [
    body('nama_petugas').trim().escape()
], cekValidasi, (req, res) => {
    const { nama_petugas, kategori_petugas, wilayah, no_sk } = req.body;
    const file_sk = req.file ? req.file.filename : null;
    if (!file_sk) return res.status(400).json({ status: "gagal", pesan: "File SK wajib diunggah!" });

    const sql = "INSERT INTO data_petugas (nama_petugas, kategori_petugas, wilayah, no_sk, file_sk) VALUES (?, ?, ?, ?, ?)";
    db.query(sql, [nama_petugas, kategori_petugas, wilayah, no_sk, file_sk], (err, result) => {
        if (err) return res.status(500).json({ status: "gagal", pesan: err.message });
        res.json({ status: "sukses", pesan: "Data Petugas disimpan!" });
    });
});

app.post('/kegiatan-gober', cekToken, upload.single('foto'), (req, res) => {
    const { petugas_id, nama_petugas, lokasi, panjang_meter } = req.body;
    const foto = req.file ? req.file.filename : null;
    if (!foto) return res.status(400).json({ status: "gagal", pesan: "Wajib melampirkan foto!" });

    const sql = "INSERT INTO kegiatan_gober (petugas_id, nama_petugas, lokasi, panjang_meter, foto) VALUES (?, ?, ?, ?, ?)";
    db.query(sql, [petugas_id, nama_petugas, lokasi, panjang_meter, foto], (err, result) => {
        if (err) return res.status(500).json({ status: "error", pesan: err.message });
        res.json({ status: "sukses", pesan: "Laporan Gober disimpan!" });
    });
});

app.get('/kegiatan-gober', cekToken, (req, res) => {
    db.query("SELECT * FROM kegiatan_gober ORDER BY tanggal_kegiatan DESC", (err, results) => {
        if (err) return res.status(500).json({ status: "error", pesan: err.message });
        res.json(results);
    });
});

// Rute Laporan Sampah (KINI MENERIMA UPLOAD FOTO)
app.post('/kegiatan-sampah', cekToken, upload.single('foto'), (req, res) => {
    const { petugas_id, nama_petugas, kategori_tugas, data_rw, berat_kiloan } = req.body;
    
    // Mesin X-Ray menangkap file foto
    const foto = req.file ? req.file.filename : null;
    
    // Validasi pencegah kecurangan: Kalau tidak kirim foto, tolak laporannya!
    if (!foto) return res.status(400).json({ status: "gagal", pesan: "Wajib melampirkan foto timbangan!" });

    const sql = "INSERT INTO kegiatan_sampah (petugas_id, nama_petugas, kategori_tugas, data_rw, berat_kiloan, foto) VALUES (?, ?, ?, ?, ?, ?)";
    db.query(sql, [petugas_id, nama_petugas, kategori_tugas, data_rw, berat_kiloan, foto], (err, result) => {
        if (err) return res.status(500).json({ status: "error", pesan: err.message });
        res.json({ status: "sukses", pesan: `Laporan ${kategori_tugas} beserta foto disimpan!` });
    });
});

app.get('/kegiatan-sampah', cekToken, (req, res) => {
    db.query("SELECT * FROM kegiatan_sampah ORDER BY tanggal_kegiatan DESC", (err, results) => {
        if (err) return res.status(500).json({ status: "error", pesan: err.message });
        res.json(results);
    });
});

app.post('/kegiatan-agenda', cekToken, upload.single('foto_dokumentasi'), (req, res) => {
    const { judul_agenda, kategori_agenda, tanggal_waktu, lokasi, catatan_reminder } = req.body;
    const foto_dokumentasi = req.file ? req.file.filename : null;

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
    const foto = req.file ? req.file.filename : null;
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
    const { kategori_lokasi, nama_lokasi, alamat, latitude, longitude, status, ketua, luas_lahan, data_rw } = req.body;
    const foto = req.file ? req.file.filename : null;

    const sql = `INSERT INTO titik_peta_gis (kategori_lokasi, nama_lokasi, alamat, latitude, longitude, foto_url, status, ketua, luas_lahan, data_rw) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`;
    const values = [kategori_lokasi, nama_lokasi, alamat, latitude, longitude, foto, status || null, ketua || null, luas_lahan || null, data_rw || null];

    db.query(sql, values, (err, result) => {
        if (err) return res.status(500).json({ status: "error", pesan: err.message });
        res.json({ status: "sukses", pesan: "Titik lokasi ditanam di peta!" });
    });
});

// Rute BARU: Mengubah Status Peta (Untuk Rutilahu)
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

// 1. POST: Mengirim permintaan reset password (TIDAK DIGEMBOK)
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

// 2. GET: Mengambil notifikasi yang belum dibaca (DIGEMBOK JWT)
app.get('/notifikasi', cekToken, (req, res) => {
    const sql = `SELECT * FROM notifikasi_sistem WHERE status = 'Belum Dibaca' ORDER BY tanggal DESC`;
    db.query(sql, (err, results) => {
        if (err) return res.status(500).json({ status: "error", pesan: "Gagal menarik data notifikasi." });
        res.json({ status: "sukses", data: results });
    });
});

// 3. PUT: Menandai notifikasi sebagai 'Sudah Dibaca' (DIGEMBOK JWT)
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
app.listen(PORT, () => {
    console.log(`Server digembok dan berjalan aman di port ${PORT}`);
});