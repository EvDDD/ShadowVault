# 🔐 ShadowVault

**Personal Password Manager with Steganography-Based Storage**

ShadowVault là một ứng dụng quản lý mật khẩu cá nhân, sử dụng mã hóa đa tầng và kỹ thuật giấu tin trong ảnh (steganography) để bảo vệ dữ liệu. Cơ sở dữ liệu **không bao giờ tồn tại dưới dạng file trên ổ đĩa** — toàn bộ dữ liệu được nhúng vào ảnh PNG bằng kỹ thuật LSB (Least Significant Bit) và chỉ sống trong bộ nhớ RAM khi ứng dụng đang chạy.

---

## ✨ Tính năng chính

- 🔑 **Mã hóa đa tầng** — Master Password → KEK → RSA Private Key → DEK → Vault Entries
- 🖼️ **Steganography** — CSDL được giấu bên trong ảnh PNG, trông giống ảnh bình thường
- 🧮 **RSA tự triển khai** — Sinh khóa RSA-2048 từ đầu (BigInt, Miller-Rabin, CSPRNG) không dùng thư viện ngoài
- 🛡️ **AES-256-GCM** — Authenticated encryption cho toàn bộ dữ liệu nhạy cảm
- 🔄 **Recovery** — Emergency Recovery Key (128-bit) và Secret Questions
- 🎲 **Password Generator** — Sinh mật khẩu mạnh với tuỳ chọn linh hoạt
- 📊 **Health Check** — Phân tích độ mạnh (Shannon Entropy + zxcvbn), phát hiện mật khẩu trùng lặp
- 🎭 **Decoy Images** — Tự động tạo ảnh ngụy trang trong thư mục lưu trữ
- 🌙 **Dark Theme UI** — Giao diện PyQt6 hiện đại

---

## 🏗️ Kiến trúc mã hóa

```
Master Password ──PBKDF2 (600K iter)──► KEK ──AES-GCM──► [RSA Private Key]
RSA Private Key ──RSA decrypt (CRT)──►  DEK
RSA Public Key  ──RSA encrypt──►        [Encrypted DEK]  (stored in DB)
DEK ──AES-GCM──► Vault Entries (password, url, username, notes)
```

### Luồng tạo Vault

```
create_vault()
├── generate_dek()            ← CSPRNG, 256-bit
├── generate_rsa_keypair()    ← BigInt + Miller-Rabin, RSA-2048
├── rsa_encrypt_dek()         ← RSA(pub, DEK)
├── derive_kek()              ← PBKDF2-HMAC-SHA256, 600K iterations
├── wrap_rsa_private()        ← AES-256-GCM(KEK, RSA_priv)
├── make_verification()       ← AES-256-GCM(KEK, sentinel)
└── store_recovery_key()      ← CSPRNG + PBKDF2 + AES-256-GCM
```

### Luồng mở khoá Vault

```
unlock_vault()
├── derive_kek()              ← PBKDF2(password, salt)
├── verify_kek()              ← AES-GCM decrypt sentinel
├── unwrap_rsa_private()      ← AES-GCM decrypt → RSAKeyPair
└── rsa_decrypt_dek()         ← RSA decrypt (CRT) → DEK
```

### Vòng đời Steganography

```
[Khởi động]                         [Tắt ứng dụng]
Scan ~/.shadowvault/*.png           dump_db_to_bytes()
  → peek_magic("SVLT")               → gzip.compress()
  → unhide() → gzip.decompress()       → hide() → ghi đè LSB
  → load_db_from_bytes() → RAM           vào ảnh stego
```

---

## 📁 Cấu trúc dự án

```
ShadowVault/
├── main.py                  # Entry point — khởi tạo app, stego lifecycle
├── requirements.txt         # Dependencies
│
├── core/                    # Logic nghiệp vụ & mật mã
│   ├── bigint.py            # BigInt tự triển khai (base-2³², arbitrary-precision)
│   ├── keygen.py            # CSPRNG, Miller-Rabin, RSA key generation
│   ├── crypto.py            # AES-256-GCM, PBKDF2, RSA encrypt/decrypt DEK
│   ├── vault.py             # Vault CRUD, unlock, change password
│   ├── recovery.py          # Recovery Key & Secret Questions
│   ├── password_gen.py      # Password generator, strength check, health audit
│   ├── steganography.py     # LSB hide/unhide
│   └── stego_manager.py     # Stego lifecycle manager (extract/embed DB)
│
├── db/                      # Tầng dữ liệu
│   └── schema.py            # SQLite in-memory schema, serialize/deserialize
│
├── ui/                      # Giao diện PyQt6
│   ├── main_window.py       # Cửa sổ chính
│   ├── login_dialog.py      # Đăng nhập / Tạo vault
│   ├── entry_dialog.py      # Thêm/Sửa entry
│   ├── vault_view.py        # Danh sách entries
│   ├── health_view.py       # Báo cáo sức khoẻ mật khẩu
│   ├── recovery_dialog.py   # Khôi phục bằng Recovery Key / Secret Questions
│   ├── recovery_key_dialog.py  # Hiển thị Recovery Key
│   ├── stego_dialog.py      # Quản lý ảnh stego
│   └── styles.py            # Dark theme stylesheet
│
├── tests/                   # Unit tests & Integration tests
│   ├── test_bigint.py
│   ├── test_crypto.py
│   ├── test_keygen.py
│   ├── test_password_gen.py
│   ├── test_schema.py
│   ├── test_steganography.py
│   ├── test_vault_recovery.py
│   └── test_integration.py
│
└── docs/                    # Tài liệu
    ├── thiet_ke_chi_tiet.md # Thiết kế chi tiết các hàm
    ├── test_plan.md         # Kế hoạch kiểm thử
    ├── dfd_level_0_*.png    # DFD Level 0
    └── dfd_level_1_*.png    # DFD Level 1
```

---

## 🚀 Cài đặt & Chạy

### Yêu cầu hệ thống

- **Python** ≥ 3.11 (cần `sqlite3.Connection.serialize/deserialize`)
- **OS:** Windows / macOS / Linux

### Cài đặt

```bash
# Clone repository
git clone https://github.com/<your-username>/ShadowVault.git
cd ShadowVault

# Tạo virtual environment (khuyến nghị)
python -m venv venv
# Windows
venv\Scripts\activate
# macOS/Linux
source venv/bin/activate

# Cài đặt dependencies
pip install -r requirements.txt
```

### Chạy ứng dụng

```bash
python main.py
```

Khi chạy lần đầu, ứng dụng sẽ yêu cầu:
1. Đặt **Master Password** (≥ 8 ký tự)
2. Chọn **ảnh bìa** (cover image) — ảnh PNG sẽ chứa dữ liệu vault
3. Lưu lại **Emergency Recovery Key** — chuỗi hex 128-bit, dùng khi quên mật khẩu

---

## 📦 Dependencies

| Thư viện | Phiên bản | Mục đích |
|---|---|---|
| **PyQt6** | ≥ 6.6.0 | Giao diện đồ hoạ (GUI) |
| **cryptography** | ≥ 42.0.0 | AES-256-GCM (symmetric encryption) |
| **argon2-cffi** | ≥ 23.1.0 | KDF hỗ trợ (dự phòng) |
| **Pillow** | ≥ 10.0.0 | Xử lý ảnh cho steganography |
| **pyperclip** | ≥ 1.8.2 | Copy mật khẩu vào clipboard |
| **zxcvbn** | ≥ 4.4.28 | Đánh giá độ mạnh mật khẩu |

> **Lưu ý:** RSA, BigInt, CSPRNG, Miller-Rabin, LSB Steganography đều được **tự triển khai từ đầu**, chỉ dùng Python stdlib (`os`, `hashlib`, `struct`).

---

## 🔒 Chi tiết bảo mật

### Các thuật toán tự triển khai

| Thành phần | Thuật toán | File |
|---|---|---|
| Số nguyên lớn | Base-2³² word array, Schoolbook multiplication, Knuth Division | `core/bigint.py` |
| Sinh số ngẫu nhiên | Hash-based DRBG (SHA-256 counter mode, NIST SP 800-90A) | `core/keygen.py` |
| Kiểm tra nguyên tố | Miller-Rabin (20 rounds, error < 10⁻¹²) | `core/keygen.py` |
| Sinh khoá RSA | RSA-2048 (Carmichael totient, Extended Euclidean) | `core/keygen.py` |
| RSA Decrypt | CRT optimization (Chinese Remainder Theorem) | `core/keygen.py` |
| Giấu tin trong ảnh | LSB Substitution trên kênh RGB | `core/steganography.py` |

### Các thuật toán dùng thư viện

| Thành phần | Thuật toán | Thư viện |
|---|---|---|
| Mã hoá đối xứng | AES-256-GCM | `cryptography` |
| Dẫn xuất khoá | PBKDF2-HMAC-SHA256 (600K iter) | `hashlib` (stdlib) |
| Đánh giá mật khẩu | zxcvbn + Shannon Entropy | `zxcvbn` |

### Mô hình lưu trữ

```
~/.shadowvault/
├── sunset.png          ← ảnh ngụy trang (decoy)
├── beach.png           ← ảnh ngụy trang (decoy)
├── vacation.png        ← ẢNH STEGO — chứa DB (trông giống ảnh thường)
├── family_dinner.png   ← ảnh ngụy trang (decoy)
└── ...
```

- Không có file cấu hình, không có database file
- Ảnh stego được nhận dạng bằng magic header `"SVLT"` trong LSB
- DB được nén gzip trước khi nhúng → giảm dung lượng payload

---

## 🧪 Kiểm thử

```bash
# Chạy toàn bộ test
pytest tests/ -v

# Chạy theo module
pytest tests/test_bigint.py -v
pytest tests/test_crypto.py -v
pytest tests/test_keygen.py -v
pytest tests/test_steganography.py -v
pytest tests/test_integration.py -v
```

### Phạm vi kiểm thử

- **Unit tests:** BigInt, CSPRNG, Miller-Rabin, AES, PBKDF2, Password Generator, DB Schema
- **Integration tests:** Toàn bộ luồng create → unlock → add entry → recovery → steganography

---

## 📖 Tài liệu

- [`docs/thiet_ke_chi_tiet.md`](docs/thiet_ke_chi_tiet.md) — Thiết kế chi tiết các hàm và thuật toán
- [`docs/test_plan.md`](docs/test_plan.md) — Kế hoạch kiểm thử
- [`docs/dfd_level_0_*.png`](docs/) — Sơ đồ DFD Level 0
- [`docs/dfd_level_1_*.png`](docs/) — Sơ đồ DFD Level 1

---

## 🛠️ Công nghệ sử dụng

- **Ngôn ngữ:** Python 3.11+
- **GUI Framework:** PyQt6
- **Database:** SQLite (in-memory only)
- **Cryptography:** Tự triển khai RSA-2048 + thư viện `cryptography` cho AES-GCM
- **Steganography:** LSB Substitution (tự triển khai)

---

## 📄 License

Đồ án học tập — ShadowVault.