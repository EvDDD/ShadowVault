# Test Plan & Test Cases — ShadowVault

## 1. Tổng quan Test Plan

### 1.1. Mục tiêu

Đảm bảo tất cả chức năng của ShadowVault hoạt động đúng, bảo mật và ổn định trước khi triển khai. Bao gồm kiểm thử đơn vị (unit test), kiểm thử tích hợp (integration test) và kiểm thử hệ thống (system test).

### 1.2. Phạm vi kiểm thử

| Module | Chức năng kiểm thử |
|---|---|
| `bigint.py` | Các phép toán số nguyên lớn |
| `keygen.py` | CSPRNG, Miller-Rabin, sinh số nguyên tố, RSA |
| `crypto.py` | PBKDF2, AES-256-GCM, RSA encrypt/decrypt, wrap/unwrap |
| `vault.py` | Tạo vault, unlock, CRUD entry, đổi mật khẩu |
| `recovery.py` | Recovery key, câu hỏi bí mật |
| `password_gen.py` | Sinh mật khẩu, đánh giá độ mạnh, health check |
| `steganography.py` | Nhúng/trích xuất LSB |
| `stego_manager.py` | Vòng đời stego, decoy images |
| `schema.py` | Serialize/deserialize DB, quản lý in-memory |

### 1.3. Phương pháp kiểm thử

| Cấp độ | Phương pháp | Mô tả |
|---|---|---|
| Unit Test | White-box & Black-box | Kiểm thử từng hàm riêng lẻ, đầu vào/đầu ra |
| Integration Test | Black-box | Kiểm thử luồng dữ liệu giữa các module |
| System Test | Black-box | Kiểm thử toàn bộ quy trình từ góc nhìn người dùng |

### 1.4. Môi trường kiểm thử

- Python ≥ 3.11
- Windows 10/11
- SQLite in-memory (không cần cài đặt DB server)
- Thư viện: Pillow, cryptography, zxcvbn (tùy chọn)

### 1.5. Tiêu chí hoàn thành

- 100% test case ở mức Unit Test và Integration Test phải PASS
- 100% test case ở mức System Test phải PASS
- Không có lỗi bảo mật nghiêm trọng (key leak, plaintext trên đĩa)

---

## 2. Unit Test

### 2.1. Module `bigint` — Số nguyên lớn

| Mã TC | Tên | Loại |
|---|---|---|
| **TC-BI-001** | **Khởi tạo BigInt từ int** | Black-box |

| | Chi tiết |
|---|---|
| **Điều kiện tiên quyết** | Không |
| **Dữ liệu đầu vào** | Các giá trị: 0, 1, 255, 2^64, 2^1024 |
| **Các bước** | 1. Tạo `BigInt(value)` <br> 2. Gọi `to_int()` |
| **Kết quả mong đợi** | `to_int()` trả về đúng giá trị ban đầu cho mọi trường hợp |

---

| Mã TC | Tên | Loại |
|---|---|---|
| **TC-BI-002** | **Phép cộng BigInt** | White-box |

| | Chi tiết |
|---|---|
| **Dữ liệu đầu vào** | `a = BigInt(2^512 - 1)`, `b = BigInt(1)` |
| **Các bước** | 1. `c = a + b` |
| **Kết quả mong đợi** | `c.to_int() == 2^512`; kiểm tra carry propagation qua nhiều word |

---

| Mã TC | Tên | Loại |
|---|---|---|
| **TC-BI-003** | **Phép trừ BigInt** | Black-box |

| | Chi tiết |
|---|---|
| **Dữ liệu đầu vào** | `a = BigInt(1000)`, `b = BigInt(999)` |
| **Các bước** | 1. `c = a - b` <br> 2. `d = b - a` (trường hợp lỗi) |
| **Kết quả mong đợi** | `c == 1`; bước 2 raise `ArithmeticError` |

---

| Mã TC | Tên | Loại |
|---|---|---|
| **TC-BI-004** | **Phép nhân BigInt** | Black-box |

| | Chi tiết |
|---|---|
| **Dữ liệu đầu vào** | `a = BigInt(2^256)`, `b = BigInt(2^256)` |
| **Các bước** | 1. `c = a * b` |
| **Kết quả mong đợi** | `c.to_int() == 2^512` |

---

| Mã TC | Tên | Loại |
|---|---|---|
| **TC-BI-005** | **Phép chia và modulo BigInt** | White-box |

| | Chi tiết |
|---|---|
| **Dữ liệu đầu vào** | `a = BigInt(12345678901234567890)`, `b = BigInt(9876543210)` |
| **Các bước** | 1. `q = a // b` <br> 2. `r = a % b` |
| **Kết quả mong đợi** | `q * b + r == a`; chia cho 0 raise `ZeroDivisionError` |

---

| Mã TC | Tên | Loại |
|---|---|---|
| **TC-BI-006** | **GCD (thuật toán Euclid)** | Black-box |

| | Chi tiết |
|---|---|
| **Dữ liệu đầu vào** | `a = BigInt(48)`, `b = BigInt(18)` |
| **Các bước** | 1. `g = a.gcd(b)` |
| **Kết quả mong đợi** | `g == 6`; thêm test `gcd(0, n) == n` và `gcd(n, n) == n` |

---

| Mã TC | Tên | Loại |
|---|---|---|
| **TC-BI-007** | **Nghịch đảo modular (Extended Euclidean)** | White-box |

| | Chi tiết |
|---|---|
| **Dữ liệu đầu vào** | `a = BigInt(65537)`, `m = BigInt(phi_n)` (một giá trị phi Euler) |
| **Các bước** | 1. `d = a.mod_inverse(m)` <br> 2. Tính `(a * d) % m` |
| **Kết quả mong đợi** | `(a * d) % m == 1`; nếu `gcd(a, m) ≠ 1` → raise `ValueError` |

---

| Mã TC | Tên | Loại |
|---|---|---|
| **TC-BI-008** | **pow_mod (lũy thừa modular)** | Black-box |

| | Chi tiết |
|---|---|
| **Dữ liệu đầu vào** | `base = BigInt(2)`, `exp = BigInt(10)`, `mod = BigInt(1000)` |
| **Các bước** | 1. `result = base.pow_mod(exp, mod)` |
| **Kết quả mong đợi** | `result == 24` (2^10 = 1024 mod 1000 = 24) |

---

### 2.2. Module `keygen` — Sinh khóa

| Mã TC | Tên | Loại |
|---|---|---|
| **TC-KG-001** | **CSPRNG sinh bytes ngẫu nhiên** | Black-box |

| | Chi tiết |
|---|---|
| **Các bước** | 1. `rng = CSPRNG()` <br> 2. `b1 = rng.random_bytes(32)` <br> 3. `b2 = rng.random_bytes(32)` |
| **Kết quả mong đợi** | `len(b1) == 32`; `b1 ≠ b2` (hai lần gọi khác nhau) |

---

| Mã TC | Tên | Loại |
|---|---|---|
| **TC-KG-002** | **Miller-Rabin nhận diện số nguyên tố đúng** | White-box |

| | Chi tiết |
|---|---|
| **Dữ liệu đầu vào** | Các số nguyên tố đã biết: 2, 3, 17, 997, 104729 |
| **Các bước** | 1. Gọi `miller_rabin(BigInt(p), rng)` cho mỗi số p |
| **Kết quả mong đợi** | Tất cả trả `True` |

---

| Mã TC | Tên | Loại |
|---|---|---|
| **TC-KG-003** | **Miller-Rabin phát hiện hợp số** | White-box |

| | Chi tiết |
|---|---|
| **Dữ liệu đầu vào** | Các hợp số: 4, 15, 100, 561 (Carmichael number), 1000000 |
| **Các bước** | 1. Gọi `miller_rabin(BigInt(n), rng)` cho mỗi số n |
| **Kết quả mong đợi** | Tất cả trả `False` |

---

| Mã TC | Tên | Loại |
|---|---|---|
| **TC-KG-004** | **generate_prime sinh đúng số bit** | Black-box |

| | Chi tiết |
|---|---|
| **Dữ liệu đầu vào** | `bits = 512` |
| **Các bước** | 1. `p = generate_prime(512, rng)` <br> 2. Kiểm tra `p.bit_length()` <br> 3. Kiểm tra `miller_rabin(p, rng)` |
| **Kết quả mong đợi** | `p.bit_length() == 512`; `miller_rabin(p) == True` |

---

| Mã TC | Tên | Loại |
|---|---|---|
| **TC-KG-005** | **generate_rsa sinh cặp khóa RSA hợp lệ** | Black-box |

| | Chi tiết |
|---|---|
| **Các bước** | 1. `kp = generate_rsa(bits=1024)` (dùng 1024 cho tốc độ test) <br> 2. Kiểm tra `kp.e == 65537` <br> 3. Kiểm tra `(kp.e * kp.d) % lcm(kp.p-1, kp.q-1) == 1` <br> 4. Kiểm tra `kp.n == kp.p * kp.q` |
| **Kết quả mong đợi** | Tất cả điều kiện đúng |

---

| Mã TC | Tên | Loại |
|---|---|---|
| **TC-KG-006** | **RSA encrypt → decrypt roundtrip** | Black-box |

| | Chi tiết |
|---|---|
| **Dữ liệu đầu vào** | `message = BigInt(123456789)` |
| **Các bước** | 1. `c = kp.encrypt(message)` <br> 2. `m = kp.decrypt(c)` |
| **Kết quả mong đợi** | `m == message` |

---

### 2.3. Module `crypto` — Mã hóa

| Mã TC | Tên | Loại |
|---|---|---|
| **TC-CR-001** | **derive_kek trả về KEK deterministic** | Black-box |

| | Chi tiết |
|---|---|
| **Dữ liệu đầu vào** | `password = "MyStr0ng!Pass"`, `salt = 32 bytes` |
| **Các bước** | 1. `kek1 = derive_kek(password, salt)` <br> 2. `kek2 = derive_kek(password, salt)` |
| **Kết quả mong đợi** | `len(kek1) == 32`; `kek1 == kek2` |

---

| Mã TC | Tên | Loại |
|---|---|---|
| **TC-CR-002** | **Sai password → KEK khác** | Black-box |

| | Chi tiết |
|---|---|
| **Dữ liệu đầu vào** | `password1 = "Pass1"`, `password2 = "Pass2"`, cùng salt |
| **Các bước** | 1. `kek1 = derive_kek(password1, salt)` <br> 2. `kek2 = derive_kek(password2, salt)` |
| **Kết quả mong đợi** | `kek1 ≠ kek2` |

---

| Mã TC | Tên | Loại |
|---|---|---|
| **TC-CR-003** | **AES-GCM encrypt → decrypt roundtrip** | Black-box |

| | Chi tiết |
|---|---|
| **Dữ liệu đầu vào** | `key = 32 bytes`, `plaintext = b"Hello ShadowVault"` |
| **Các bước** | 1. `blob = aes_encrypt(key, plaintext)` <br> 2. `result = aes_decrypt(key, blob)` |
| **Kết quả mong đợi** | `result == plaintext`; `len(blob) == 12 + len(plaintext) + 16` |

---

| Mã TC | Tên | Loại |
|---|---|---|
| **TC-CR-004** | **AES-GCM decrypt với sai key → InvalidTag** | Black-box |

| | Chi tiết |
|---|---|
| **Dữ liệu đầu vào** | `key1, key2` (khác nhau), `plaintext` |
| **Các bước** | 1. `blob = aes_encrypt(key1, plaintext)` <br> 2. `aes_decrypt(key2, blob)` |
| **Kết quả mong đợi** | Bước 2 raise `InvalidTag` |

---

| Mã TC | Tên | Loại |
|---|---|---|
| **TC-CR-005** | **AES-GCM phát hiện dữ liệu bị sửa đổi** | White-box |

| | Chi tiết |
|---|---|
| **Các bước** | 1. `blob = aes_encrypt(key, plaintext)` <br> 2. Sửa 1 byte trong blob <br> 3. `aes_decrypt(key, modified_blob)` |
| **Kết quả mong đợi** | Bước 3 raise `InvalidTag` (đảm bảo toàn vẹn dữ liệu) |

---

| Mã TC | Tên | Loại |
|---|---|---|
| **TC-CR-006** | **Wrap/Unwrap RSA private key** | Black-box |

| | Chi tiết |
|---|---|
| **Các bước** | 1. `kp = generate_rsa_keypair()` <br> 2. `blob = wrap_rsa_private(kek, kp)` <br> 3. `kp2 = unwrap_rsa_private(kek, blob)` |
| **Kết quả mong đợi** | `kp2.n == kp.n` và `kp2.d == kp.d` (private key khôi phục đúng) |

---

| Mã TC | Tên | Loại |
|---|---|---|
| **TC-CR-007** | **RSA encrypt/decrypt DEK roundtrip** | Black-box |

| | Chi tiết |
|---|---|
| **Dữ liệu đầu vào** | `dek = 32 bytes ngẫu nhiên` |
| **Các bước** | 1. `enc = rsa_encrypt_dek(kp, dek)` <br> 2. `dec = rsa_decrypt_dek(kp, enc)` |
| **Kết quả mong đợi** | `dec == dek` |

---

| Mã TC | Tên | Loại |
|---|---|---|
| **TC-CR-008** | **verify_kek đúng/sai** | Black-box |

| | Chi tiết |
|---|---|
| **Các bước** | 1. `token = make_verification(kek)` <br> 2. `verify_kek(kek, token)` <br> 3. `verify_kek(wrong_kek, token)` |
| **Kết quả mong đợi** | Bước 2 → `True`; Bước 3 → `False` |

---

### 2.4. Module `steganography` — Giấu tin LSB

| Mã TC | Tên | Loại |
|---|---|---|
| **TC-ST-001** | **hide → unhide roundtrip** | Black-box |

| | Chi tiết |
|---|---|
| **Dữ liệu đầu vào** | Ảnh PNG 100×100, `payload = b"secret data 12345"` |
| **Các bước** | 1. `hide(cover, payload, output)` <br> 2. `result = unhide(output)` |
| **Kết quả mong đợi** | `result == payload` |

---

| Mã TC | Tên | Loại |
|---|---|---|
| **TC-ST-002** | **Payload quá lớn → báo lỗi** | Black-box |

| | Chi tiết |
|---|---|
| **Dữ liệu đầu vào** | Ảnh 10×10 (capacity = 37 bytes), `payload = 100 bytes` |
| **Các bước** | 1. `hide(cover, payload, output)` |
| **Kết quả mong đợi** | Raise lỗi capacity không đủ |

---

| Mã TC | Tên | Loại |
|---|---|---|
| **TC-ST-003** | **peek_magic nhận diện ảnh stego** | Black-box |

| | Chi tiết |
|---|---|
| **Các bước** | 1. Tạo ảnh stego bằng `hide()` <br> 2. `peek_magic(stego_path)` <br> 3. `peek_magic(normal_image_path)` |
| **Kết quả mong đợi** | Bước 2 → `True`; Bước 3 → `False` |

---

| Mã TC | Tên | Loại |
|---|---|---|
| **TC-ST-004** | **Ảnh stego không thay đổi kích thước** | White-box |

| | Chi tiết |
|---|---|
| **Các bước** | 1. Đo kích thước ảnh gốc (width, height) <br> 2. `hide(cover, payload, output)` <br> 3. Đo kích thước ảnh stego |
| **Kết quả mong đợi** | Kích thước pixel ảnh gốc = ảnh stego |

---

### 2.5. Module `password_gen` — Sinh và đánh giá mật khẩu

| Mã TC | Tên | Loại |
|---|---|---|
| **TC-PG-001** | **Sinh mật khẩu đúng độ dài** | Black-box |

| | Chi tiết |
|---|---|
| **Dữ liệu đầu vào** | `length = 20` |
| **Các bước** | 1. `pw = generate_password(length=20)` |
| **Kết quả mong đợi** | `len(pw) == 20` |

---

| Mã TC | Tên | Loại |
|---|---|---|
| **TC-PG-002** | **Mật khẩu chứa đủ loại ký tự** | Black-box |

| | Chi tiết |
|---|---|
| **Các bước** | 1. `pw = generate_password(use_upper=True, use_lower=True, use_digits=True, use_symbols=True)` |
| **Kết quả mong đợi** | pw chứa ≥1 chữ hoa, ≥1 chữ thường, ≥1 chữ số, ≥1 ký tự đặc biệt |

---

| Mã TC | Tên | Loại |
|---|---|---|
| **TC-PG-003** | **exclude_ambiguous loại ký tự nhầm lẫn** | Black-box |

| | Chi tiết |
|---|---|
| **Các bước** | 1. Sinh 100 mật khẩu với `exclude_ambiguous=True` |
| **Kết quả mong đợi** | Không có mật khẩu nào chứa ký tự: l, O, 0, 1, I |

---

| Mã TC | Tên | Loại |
|---|---|---|
| **TC-PG-004** | **check_strength đánh giá mật khẩu yếu** | Black-box |

| | Chi tiết |
|---|---|
| **Dữ liệu đầu vào** | `password = "123456"` |
| **Các bước** | 1. `result = check_strength("123456")` |
| **Kết quả mong đợi** | `result.score <= 1` (Weak hoặc Very Weak) |

---

| Mã TC | Tên | Loại |
|---|---|---|
| **TC-PG-005** | **check_strength đánh giá mật khẩu mạnh** | Black-box |

| | Chi tiết |
|---|---|
| **Dữ liệu đầu vào** | `password = "kX9!mN#pQ2@wZ7&vR4"` |
| **Các bước** | 1. `result = check_strength(password)` |
| **Kết quả mong đợi** | `result.score >= 3` (Strong hoặc Very Strong) |

---

| Mã TC | Tên | Loại |
|---|---|---|
| **TC-PG-006** | **check_all_health phát hiện mật khẩu trùng lặp** | Black-box |

| | Chi tiết |
|---|---|
| **Dữ liệu đầu vào** | 3 VaultEntry, trong đó 2 entry dùng cùng password "abc123" |
| **Các bước** | 1. `issues = check_all_health(entries)` |
| **Kết quả mong đợi** | Danh sách issues chứa ≥2 HealthIssue với `issue_type == "duplicate"` |

---

### 2.6. Module `schema` — CSDL

| Mã TC | Tên | Loại |
|---|---|---|
| **TC-DB-001** | **Serialize → Deserialize DB roundtrip** | Black-box |

| | Chi tiết |
|---|---|
| **Các bước** | 1. `init_db()` → INSERT dữ liệu test <br> 2. `data = dump_db_to_bytes()` <br> 3. `close_db()` → `init_db()` <br> 4. `load_db_from_bytes(data)` <br> 5. SELECT dữ liệu |
| **Kết quả mong đợi** | Dữ liệu ở bước 5 giống dữ liệu INSERT ở bước 1 |

---

| Mã TC | Tên | Loại |
|---|---|---|
| **TC-DB-002** | **Foreign key cascade delete** | White-box |

| | Chi tiết |
|---|---|
| **Các bước** | 1. Tạo vault + entries <br> 2. DELETE vault <br> 3. SELECT entries của vault đã xóa |
| **Kết quả mong đợi** | Bước 3 trả về 0 row (cascade delete) |

---

| Mã TC | Tên | Loại |
|---|---|---|
| **TC-DB-003** | **vault_exists kiểm tra đúng trạng thái** | Black-box |

| | Chi tiết |
|---|---|
| **Các bước** | 1. `init_db()` → `vault_exists()` <br> 2. INSERT 1 vault <br> 3. `vault_exists()` |
| **Kết quả mong đợi** | Bước 1 → `False`; Bước 3 → `True` |

---

| Mã TC | Tên | Loại |
|---|---|---|
| **TC-DB-004** | **close_db hủy toàn bộ dữ liệu** | White-box |

| | Chi tiết |
|---|---|
| **Các bước** | 1. `init_db()` → INSERT dữ liệu <br> 2. `close_db()` <br> 3. `init_db()` → SELECT dữ liệu |
| **Kết quả mong đợi** | Bước 3 trả về 0 row (DB in-memory đã bị hủy hoàn toàn) |

---

### 2.7. Module `vault` — Quản lý Vault

| Mã TC | Tên | Loại |
|---|---|---|
| **TC-VT-001** | **Tạo vault thành công** | Black-box |

| | Chi tiết |
|---|---|
| **Điều kiện tiên quyết** | `init_db()` đã chạy |
| **Dữ liệu đầu vào** | `master_password = "Test@1234"`, `vault_name = "Test Vault"` |
| **Các bước** | 1. `dek, recovery, vid = create_vault(master_password, vault_name)` |
| **Kết quả mong đợi** | `len(dek) == 32`; `recovery` là chuỗi hex hợp lệ (format XXXXXXXX-XXXXXXXX-...); `vid > 0` |

---

| Mã TC | Tên | Loại |
|---|---|---|
| **TC-VT-002** | **Unlock vault đúng password** | Black-box |

| | Chi tiết |
|---|---|
| **Điều kiện tiên quyết** | Vault đã tạo bằng TC-VT-001 |
| **Các bước** | 1. `dek2 = unlock_vault("Test@1234", vid)` |
| **Kết quả mong đợi** | `dek2 == dek` (cùng DEK với lúc tạo) |

---

| Mã TC | Tên | Loại |
|---|---|---|
| **TC-VT-003** | **Unlock vault sai password → None** | Black-box |

| | Chi tiết |
|---|---|
| **Các bước** | 1. `result = unlock_vault("WrongPassword!", vid)` |
| **Kết quả mong đợi** | `result is None` |

---

| Mã TC | Tên | Loại |
|---|---|---|
| **TC-VT-004** | **Thêm entry và lấy lại đúng** | Black-box |

| | Chi tiết |
|---|---|
| **Dữ liệu đầu vào** | VaultEntry(title="Google", url="google.com", username="user@gmail.com", password="secret123", notes="test") |
| **Các bước** | 1. `eid = add_entry(dek, entry)` <br> 2. `e = get_entry(dek, eid)` |
| **Kết quả mong đợi** | `e.title == "Google"`; `e.url == "google.com"`; `e.password == "secret123"` |

---

| Mã TC | Tên | Loại |
|---|---|---|
| **TC-VT-005** | **Cập nhật entry** | Black-box |

| | Chi tiết |
|---|---|
| **Các bước** | 1. Thêm entry với password="old" <br> 2. Sửa password="new" → `update_entry(dek, entry)` <br> 3. `e = get_entry(dek, eid)` |
| **Kết quả mong đợi** | `e.password == "new"` |

---

| Mã TC | Tên | Loại |
|---|---|---|
| **TC-VT-006** | **Xóa entry** | Black-box |

| | Chi tiết |
|---|---|
| **Các bước** | 1. Thêm entry → `eid` <br> 2. `delete_entry(eid)` <br> 3. `get_entry(dek, eid)` |
| **Kết quả mong đợi** | Bước 3 trả về `None` |

---

| Mã TC | Tên | Loại |
|---|---|---|
| **TC-VT-007** | **Tìm kiếm entry theo keyword** | Black-box |

| | Chi tiết |
|---|---|
| **Điều kiện tiên quyết** | Thêm 3 entry: "Google", "Facebook", "Gmail" |
| **Các bước** | 1. `results = get_all_entries(dek, search="goo")` |
| **Kết quả mong đợi** | Trả về 1 entry (chỉ "Google") |

---

| Mã TC | Tên | Loại |
|---|---|---|
| **TC-VT-008** | **Đổi master password** | Black-box |

| | Chi tiết |
|---|---|
| **Các bước** | 1. `create_vault("OldPass")` → dek <br> 2. `change_master_password(dek, "NewPass")` <br> 3. `unlock_vault("OldPass")` <br> 4. `unlock_vault("NewPass")` |
| **Kết quả mong đợi** | Bước 2 → `True`; Bước 3 → `None`; Bước 4 → `dek` (DEK không đổi) |

---

| Mã TC | Tên | Loại |
|---|---|---|
| **TC-VT-009** | **Xóa vault cascade** | White-box |

| | Chi tiết |
|---|---|
| **Các bước** | 1. Tạo vault + thêm 3 entries <br> 2. `delete_vault(vid)` <br> 3. SELECT entries, user_auth, key_store của vault đã xóa |
| **Kết quả mong đợi** | Tất cả bảng liên quan trả về 0 row |

---

| Mã TC | Tên | Loại |
|---|---|---|
| **TC-VT-010** | **Entry fields được mã hóa trong DB** | White-box |

| | Chi tiết |
|---|---|
| **Các bước** | 1. `add_entry(dek, entry)` với password="MySecret" <br> 2. SELECT trực tiếp `enc_password` từ `vault_entry` |
| **Kết quả mong đợi** | `enc_password` là bytes (không phải plaintext "MySecret") |

---

### 2.8. Module `recovery` — Khôi phục mật khẩu

| Mã TC | Tên | Loại |
|---|---|---|
| **TC-RC-001** | **Recovery key mở khóa thành công** | Black-box |

| | Chi tiết |
|---|---|
| **Các bước** | 1. `dek, recovery_display, vid = create_vault("Pass")` <br> 2. `dek2 = unlock_with_recovery_key(recovery_display, vid)` |
| **Kết quả mong đợi** | `dek2 == dek` |

---

| Mã TC | Tên | Loại |
|---|---|---|
| **TC-RC-002** | **Sai recovery key → None** | Black-box |

| | Chi tiết |
|---|---|
| **Các bước** | 1. Tạo vault <br> 2. `unlock_with_recovery_key("AAAAAAAA-BBBBBBBB-CCCCCCCC-DDDDDDDD", vid)` |
| **Kết quả mong đợi** | Trả về `None` |

---

| Mã TC | Tên | Loại |
|---|---|---|
| **TC-RC-003** | **Recovery key format không hợp lệ → None** | Black-box |

| | Chi tiết |
|---|---|
| **Dữ liệu đầu vào** | `recovery_display = "invalid-key"` |
| **Các bước** | 1. `unlock_with_recovery_key("invalid-key", vid)` |
| **Kết quả mong đợi** | Trả về `None` (không crash) |

---

| Mã TC | Tên | Loại |
|---|---|---|
| **TC-RC-004** | **Lưu và mở khóa bằng câu hỏi bí mật** | Black-box |

| | Chi tiết |
|---|---|
| **Dữ liệu đầu vào** | 3 cặp câu hỏi/trả lời |
| **Các bước** | 1. `save_secret_questions(dek, [("Q1","A1"), ("Q2","A2"), ("Q3","A3")])` <br> 2. `dek2 = unlock_with_secret_questions(["A1","A2","A3"])` |
| **Kết quả mong đợi** | Bước 1 → `True`; `dek2 == dek` |

---

| Mã TC | Tên | Loại |
|---|---|---|
| **TC-RC-005** | **Sai câu trả lời → None** | Black-box |

| | Chi tiết |
|---|---|
| **Các bước** | 1. Đã lưu câu hỏi bí mật <br> 2. `unlock_with_secret_questions(["A1","WRONG","A3"])` |
| **Kết quả mong đợi** | Trả về `None` |

---

| Mã TC | Tên | Loại |
|---|---|---|
| **TC-RC-006** | **Câu trả lời case-insensitive** | White-box |

| | Chi tiết |
|---|---|
| **Các bước** | 1. Lưu câu hỏi với trả lời "Hanoi" <br> 2. `unlock_with_secret_questions(["hAnOi", ...])` |
| **Kết quả mong đợi** | Mở khóa thành công (câu trả lời được lowercase trước khi xử lý) |

---

| Mã TC | Tên | Loại |
|---|---|---|
| **TC-RC-007** | **Ít hơn 3 câu hỏi → lỗi** | Black-box |

| | Chi tiết |
|---|---|
| **Các bước** | 1. `save_secret_questions(dek, [("Q1","A1"), ("Q2","A2")])` |
| **Kết quả mong đợi** | Raise `ValueError` ("At least 3 secret questions are required") |

---

| Mã TC | Tên | Loại |
|---|---|---|
| **TC-RC-008** | **has_secret_questions kiểm tra đúng trạng thái** | Black-box |

| | Chi tiết |
|---|---|
| **Các bước** | 1. Tạo vault mới → `has_secret_questions()` <br> 2. Lưu câu hỏi bí mật → `has_secret_questions()` |
| **Kết quả mong đợi** | Bước 1 → `False`; Bước 2 → `True` |

---

### 2.9. Module `stego_manager` — Vòng đời Steganography

| Mã TC | Tên | Loại |
|---|---|---|
| **TC-SM-001** | **first_embed tạo ảnh stego** | Black-box |

| | Chi tiết |
|---|---|
| **Điều kiện tiên quyết** | `init_db()`, vault đã tạo, có ảnh cover PNG |
| **Các bước** | 1. `StegoManager.first_embed(cover_path)` <br> 2. Kiểm tra file PNG trong `~/.shadowvault/` |
| **Kết quả mong đợi** | Có ≥1 file PNG trong thư mục; `peek_magic()` trả `True` cho file đó |

---

| Mã TC | Tên | Loại |
|---|---|---|
| **TC-SM-002** | **embed_db → extract_db roundtrip** | Black-box |

| | Chi tiết |
|---|---|
| **Các bước** | 1. Tạo vault, thêm entries <br> 2. `StegoManager.embed_db()` <br> 3. `close_db()` → `init_db()` <br> 4. `StegoManager.extract_db()` <br> 5. `get_all_entries(dek)` |
| **Kết quả mong đợi** | Entries ở bước 5 giống entries đã thêm ở bước 1 |

---

| Mã TC | Tên | Loại |
|---|---|---|
| **TC-SM-003** | **find_stego_image tìm đúng ảnh stego giữa decoys** | White-box |

| | Chi tiết |
|---|---|
| **Điều kiện tiên quyết** | Thư mục chứa 1 ảnh stego + 10 ảnh decoy |
| **Các bước** | 1. `path = StegoManager.find_stego_image()` <br> 2. `peek_magic(path)` |
| **Kết quả mong đợi** | `path` trỏ đến ảnh stego thật; `peek_magic(path) == True` |

---

| Mã TC | Tên | Loại |
|---|---|---|
| **TC-SM-004** | **populate_decoys tạo đúng số ảnh** | Black-box |

| | Chi tiết |
|---|---|
| **Các bước** | 1. `created = StegoManager.populate_decoys(count=5, exclude_name="stego")` |
| **Kết quả mong đợi** | `len(created) == 5`; mỗi file tồn tại và có kích thước > 0; `peek_magic()` trả `False` cho tất cả |

---

| Mã TC | Tên | Loại |
|---|---|---|
| **TC-SM-005** | **populate_decoys không ghi đè ảnh đã tồn tại** | White-box |

| | Chi tiết |
|---|---|
| **Các bước** | 1. Chạy `populate_decoys(count=5)` → tạo 5 ảnh <br> 2. Ghi nhớ size từng file <br> 3. Chạy `populate_decoys(count=5)` lần 2 <br> 4. So sánh size |
| **Kết quả mong đợi** | Lần 2 trả danh sách rỗng; size file không đổi |

---

| Mã TC | Tên | Loại |
|---|---|---|
| **TC-SM-006** | **populate_decoys fallback khi offline** | White-box |

| | Chi tiết |
|---|---|
| **Điều kiện tiên quyết** | Chặn kết nối internet (mock urllib) |
| **Các bước** | 1. `created = StegoManager.populate_decoys(count=3)` |
| **Kết quả mong đợi** | Tạo thành công 3 ảnh (dùng gradient fallback); không crash |

---

*Phần tiếp theo: Integration Test và System Test.*

---

## 3. Integration Test

Kiểm thử luồng dữ liệu xuyên suốt giữa các module, đảm bảo các module phối hợp đúng.

### 3.1. Luồng mã hóa đa tầng (Crypto + Keygen + Vault)

| Mã TC | Tên | Loại |
|---|---|---|
| **TC-IT-001** | **Chuỗi khóa: Password → KEK → RSA → DEK → Entry** | Integration |

| | Chi tiết |
|---|---|
| **Mô tả** | Kiểm tra toàn bộ chuỗi dẫn xuất khóa hoạt động end-to-end |
| **Các bước** | 1. `derive_kek(password, salt)` → KEK <br> 2. `generate_rsa_keypair()` → keypair <br> 3. `wrap_rsa_private(kek, keypair)` → blob <br> 4. `unwrap_rsa_private(kek, blob)` → keypair2 <br> 5. `rsa_encrypt_dek(keypair2, dek)` → enc_dek <br> 6. `rsa_decrypt_dek(keypair2, enc_dek)` → dek2 <br> 7. `encrypt_field(dek2, "secret")` → cipher <br> 8. `decrypt_field(dek2, cipher)` → plaintext |
| **Kết quả mong đợi** | `keypair2.d == keypair.d`; `dek2 == dek`; `plaintext == "secret"` |

---

| Mã TC | Tên | Loại |
|---|---|---|
| **TC-IT-002** | **Tạo vault → Unlock → Truy xuất entry** | Integration |

| | Chi tiết |
|---|---|
| **Các bước** | 1. `init_db()` <br> 2. `dek, _, vid = create_vault("Pass123!")` <br> 3. `add_entry(dek, entry_google)` <br> 4. `add_entry(dek, entry_facebook)` <br> 5. `dek2 = unlock_vault("Pass123!", vid)` <br> 6. `entries = get_all_entries(dek2)` |
| **Kết quả mong đợi** | `dek2 == dek`; `len(entries) == 2`; entries chứa đúng dữ liệu đã thêm |

---

| Mã TC | Tên | Loại |
|---|---|---|
| **TC-IT-003** | **Đổi password → Unlock bằng password mới → Entries còn nguyên** | Integration |

| | Chi tiết |
|---|---|
| **Các bước** | 1. Tạo vault ("OldPass") → thêm 3 entries <br> 2. `change_master_password(dek, "NewPass!")` <br> 3. `dek2 = unlock_vault("NewPass!")` <br> 4. `entries = get_all_entries(dek2)` |
| **Kết quả mong đợi** | `dek2 == dek`; `len(entries) == 3`; nội dung entries không đổi |

---

| Mã TC | Tên | Loại |
|---|---|---|
| **TC-IT-011** | **Sai KEK → Không thể unwrap RSA → Không lấy được DEK** | Integration |

| | Chi tiết |
|---|---|
| **Các bước** | 1. Tạo vault ("Pass1") <br> 2. `wrong_kek = derive_kek("Pass2", salt)` <br> 3. `unwrap_rsa_private(wrong_kek, kek_enc_rsa_priv)` |
| **Kết quả mong đợi** | Bước 3 raise `InvalidTag` — sai KEK không thể giải mã RSA private key |

---

| Mã TC | Tên | Loại |
|---|---|---|
| **TC-IT-012** | **Encrypt field với DEK → Decrypt với DEK khác → Thất bại** | Integration |

| | Chi tiết |
|---|---|
| **Các bước** | 1. `cipher = encrypt_field(dek1, "password123")` <br> 2. `decrypt_field(dek2, cipher)` (dek2 ≠ dek1) |
| **Kết quả mong đợi** | Bước 2 raise `InvalidTag` — chứng minh entry chỉ đọc được với DEK đúng |

---

| Mã TC | Tên | Loại |
|---|---|---|
| **TC-IT-013** | **BigInt RSA keypair → Crypto wrap → Vault create end-to-end** | Integration |

| | Chi tiết |
|---|---|
| **Mô tả** | Kiểm tra BigInt ↔ keygen ↔ crypto integration hoàn chỉnh |
| **Các bước** | 1. `rng = CSPRNG()` → `kp = generate_rsa(2048, rng)` <br> 2. Kiểm tra `kp.p` và `kp.q` qua `miller_rabin()` <br> 3. `kp.encrypt(m)` → `kp.decrypt(c)` → so sánh <br> 4. `wrap_rsa_private(kek, kp)` → `unwrap_rsa_private(kek, blob)` → so sánh |
| **Kết quả mong đợi** | Miller-Rabin confirm p,q prime; encrypt/decrypt roundtrip đúng; wrap/unwrap roundtrip đúng |

---

### 3.2. Luồng Recovery (Crypto + Recovery + Vault)

| Mã TC | Tên | Loại |
|---|---|---|
| **TC-IT-004** | **Tạo vault → Quên password → Recovery key → Truy xuất entries** | Integration |

| | Chi tiết |
|---|---|
| **Các bước** | 1. `dek, recovery, vid = create_vault("Pass")` <br> 2. `add_entry(dek, entry)` <br> 3. Giả lập quên password: `dek2 = unlock_with_recovery_key(recovery, vid)` <br> 4. `entries = get_all_entries(dek2)` |
| **Kết quả mong đợi** | `dek2 == dek`; entries truy xuất đúng |

---

| Mã TC | Tên | Loại |
|---|---|---|
| **TC-IT-005** | **Recovery key → Đổi password mới → Unlock bằng password mới** | Integration |

| | Chi tiết |
|---|---|
| **Các bước** | 1. Tạo vault → recovery key <br> 2. `dek = unlock_with_recovery_key(recovery)` <br> 3. `change_master_password(dek, "BrandNewPass!")` <br> 4. `dek2 = unlock_vault("BrandNewPass!")` |
| **Kết quả mong đợi** | `dek2 == dek` |

---

| Mã TC | Tên | Loại |
|---|---|---|
| **TC-IT-006** | **Secret questions → Khôi phục DEK → Entries đúng** | Integration |

| | Chi tiết |
|---|---|
| **Các bước** | 1. Tạo vault → thêm entries <br> 2. `save_secret_questions(dek, qa_list)` <br> 3. `dek2 = unlock_with_secret_questions(answers)` <br> 4. `entries = get_all_entries(dek2)` |
| **Kết quả mong đợi** | `dek2 == dek`; entries giải mã đúng |

---

| Mã TC | Tên | Loại |
|---|---|---|
| **TC-IT-014** | **Secret questions → Đổi password → Entries persist** | Integration |

| | Chi tiết |
|---|---|
| **Các bước** | 1. Tạo vault → thêm entries → lưu secret questions <br> 2. `dek2 = unlock_with_secret_questions(answers)` <br> 3. `change_master_password(dek2, "NewPass!")` <br> 4. `dek3 = unlock_vault("NewPass!")` <br> 5. `entries = get_all_entries(dek3)` |
| **Kết quả mong đợi** | `dek2 == dek3 == dek`; entries nguyên vẹn |

---

| Mã TC | Tên | Loại |
|---|---|---|
| **TC-IT-015** | **Đổi password → Recovery key cũ vẫn hoạt động** | Integration |

| | Chi tiết |
|---|---|
| **Mô tả** | Xác nhận recovery key không bị ảnh hưởng khi đổi master password |
| **Các bước** | 1. `dek, recovery, vid = create_vault("OldPass")` <br> 2. `change_master_password(dek, "NewPass")` <br> 3. `dek2 = unlock_with_recovery_key(recovery, vid)` |
| **Kết quả mong đợi** | `dek2 == dek` — recovery key độc lập với master password |

---

### 3.3. Luồng Steganography (Schema + Stego + Steganography)

| Mã TC | Tên | Loại |
|---|---|---|
| **TC-IT-007** | **DB → Serialize → Gzip → Hide → Unhide → Decompress → Load → Verify** | Integration |

| | Chi tiết |
|---|---|
| **Các bước** | 1. `init_db()` → tạo vault + entries <br> 2. `data = dump_db_to_bytes()` <br> 3. `compressed = gzip.compress(data)` <br> 4. `hide(cover, compressed, stego_path)` <br> 5. `payload = unhide(stego_path)` <br> 6. `decompressed = gzip.decompress(payload)` <br> 7. `close_db()` → `load_db_from_bytes(decompressed)` <br> 8. SELECT entries |
| **Kết quả mong đợi** | Entries ở bước 8 giống bước 1 |

---

| Mã TC | Tên | Loại |
|---|---|---|
| **TC-IT-008** | **StegoManager lifecycle: first_embed → embed_db → extract_db** | Integration |

| | Chi tiết |
|---|---|
| **Các bước** | 1. `init_db()` → `create_vault("Pass")` <br> 2. `StegoManager.first_embed(cover)` <br> 3. `add_entry(dek, entry)` <br> 4. `StegoManager.embed_db()` <br> 5. `close_db()` → `init_db()` <br> 6. `StegoManager.extract_db()` <br> 7. `dek2 = unlock_vault("Pass")` <br> 8. `entries = get_all_entries(dek2)` |
| **Kết quả mong đợi** | `len(entries) == 1`; entry giải mã đúng |

---

| Mã TC | Tên | Loại |
|---|---|---|
| **TC-IT-009** | **Decoy images không ảnh hưởng tìm ảnh stego** | Integration |

| | Chi tiết |
|---|---|
| **Các bước** | 1. `first_embed(cover)` <br> 2. `populate_decoys(count=10)` <br> 3. `path = find_stego_image()` <br> 4. `extract_db()` → unlock → lấy entries |
| **Kết quả mong đợi** | `find_stego_image()` trả đúng ảnh; entries truy xuất đúng; decoy không bị nhầm |

---

### 3.4. Luồng Password Health (Vault + Password Gen)

| Mã TC | Tên | Loại |
|---|---|---|
| **TC-IT-010** | **Thêm entries → Health check phát hiện vấn đề** | Integration |

| | Chi tiết |
|---|---|
| **Các bước** | 1. Tạo vault <br> 2. Thêm entry A: password="123456" (yếu) <br> 3. Thêm entry B: password="StrongP@ss99!" <br> 4. Thêm entry C: password="123456" (trùng A) <br> 5. `issues = check_all_health(get_all_entries(dek))` |
| **Kết quả mong đợi** | Issues chứa "weak" cho A và C; "duplicate" cho cả A và C |

---

| Mã TC | Tên | Loại |
|---|---|---|
| **TC-IT-016** | **Embed DB nhiều lần liên tiếp → Dữ liệu mới nhất được giữ** | Integration |

| | Chi tiết |
|---|---|
| **Các bước** | 1. Tạo vault + thêm 1 entry → `embed_db()` <br> 2. Thêm 2 entries nữa → `embed_db()` <br> 3. `close_db()` → `extract_db()` <br> 4. `get_all_entries(dek)` |
| **Kết quả mong đợi** | Trả về 3 entries (dữ liệu mới nhất, không phải snapshot lần embed đầu) |

---

| Mã TC | Tên | Loại |
|---|---|---|
| **TC-IT-017** | **Sinh password → Thêm vào vault → Health check PASS** | Integration |

| | Chi tiết |
|---|---|
| **Các bước** | 1. `pw = generate_password(length=20, use_upper=True, use_lower=True, use_digits=True, use_symbols=True)` <br> 2. `add_entry(dek, entry_with_pw)` <br> 3. `issues = check_all_health(get_all_entries(dek))` |
| **Kết quả mong đợi** | Không có issue cho entry này (password đủ mạnh, không trùng) |

---

| Mã TC | Tên | Loại |
|---|---|---|
| **TC-IT-018** | **Gzip compression giảm kích thước DB** | Integration |

| | Chi tiết |
|---|---|
| **Các bước** | 1. `data = dump_db_to_bytes()` → ghi nhận `len(data)` <br> 2. `compressed = gzip.compress(data, compresslevel=9)` → ghi nhận `len(compressed)` |
| **Kết quả mong đợi** | `len(compressed) < len(data)` — nén thành công |

---

## 4. System Test

Kiểm thử toàn bộ hệ thống từ góc nhìn người dùng cuối, mô phỏng các kịch bản sử dụng thực tế.

### 4.1. Kịch bản sử dụng chính

| Mã TC | Tên | Loại |
|---|---|---|
| **TC-SY-001** | **Kịch bản: Người dùng mới — Tạo vault lần đầu** | System |

| | Chi tiết |
|---|---|
| **Mô tả** | Mô phỏng trải nghiệm người dùng lần đầu sử dụng ShadowVault |
| **Các bước** | 1. Khởi động ứng dụng <br> 2. Chọn ảnh cover PNG <br> 3. Nhập vault name và master password <br> 4. Hệ thống hiển thị recovery key <br> 5. Xác nhận lưu recovery key <br> 6. Giao diện vault chính hiển thị (rỗng) |
| **Kết quả mong đợi** | Vault tạo thành công; recovery key hiển thị đúng format; thư mục `~/.shadowvault/` chứa ảnh stego + decoys; giao diện hiển thị đúng |

---

| Mã TC | Tên | Loại |
|---|---|---|
| **TC-SY-002** | **Kịch bản: Đăng nhập hàng ngày** | System |

| | Chi tiết |
|---|---|
| **Các bước** | 1. Khởi động ứng dụng (vault đã tồn tại) <br> 2. Nhập master password đúng <br> 3. Danh sách entries hiển thị <br> 4. Click entry → xem chi tiết, copy password <br> 5. Tắt ứng dụng |
| **Kết quả mong đợi** | Login thành công; entries hiển thị đúng; copy password hoạt động; DB được embed lại vào ảnh stego khi tắt |

---

| Mã TC | Tên | Loại |
|---|---|---|
| **TC-SY-003** | **Kịch bản: Quản lý entries đầy đủ** | System |

| | Chi tiết |
|---|---|
| **Các bước** | 1. Đăng nhập <br> 2. Thêm entry mới (nhập title, URL, username, password, notes) <br> 3. Xem entry vừa thêm <br> 4. Sửa password của entry <br> 5. Tìm kiếm entry bằng keyword <br> 6. Xóa entry <br> 7. Tắt app → mở lại → kiểm tra entries |
| **Kết quả mong đợi** | Mỗi thao tác phản hồi đúng; dữ liệu persist qua restart (embed/extract stego) |

---

| Mã TC | Tên | Loại |
|---|---|---|
| **TC-SY-004** | **Kịch bản: Sinh mật khẩu ngẫu nhiên** | System |

| | Chi tiết |
|---|---|
| **Các bước** | 1. Mở dialog thêm entry <br> 2. Click nút sinh mật khẩu <br> 3. Điều chỉnh tùy chọn (độ dài, loại ký tự) <br> 4. Sinh lại nhiều lần <br> 5. Lưu entry với password đã sinh |
| **Kết quả mong đợi** | Mỗi lần sinh ra password khác nhau; đúng độ dài và charset; thanh strength cập nhật real-time |

---

| Mã TC | Tên | Loại |
|---|---|---|
| **TC-SY-013** | **Kịch bản: Thiết lập câu hỏi bí mật** | System |

| | Chi tiết |
|---|---|
| **Các bước** | 1. Đăng nhập → mở Settings <br> 2. Chọn "Thiết lập câu hỏi bí mật" <br> 3. Nhập 3 cặp câu hỏi/trả lời <br> 4. Xác nhận lưu |
| **Kết quả mong đợi** | Thông báo lưu thành công; câu hỏi bí mật hiển thị trạng thái "Đã thiết lập" |

---

| Mã TC | Tên | Loại |
|---|---|---|
| **TC-SY-014** | **Kịch bản: Đăng nhập sai password nhiều lần** | System |

| | Chi tiết |
|---|---|
| **Các bước** | 1. Nhập sai password 5 lần liên tiếp |
| **Kết quả mong đợi** | Mỗi lần hiển thị thông báo "Sai mật khẩu"; ứng dụng không crash; không lộ thông tin về password đúng |

---

| Mã TC | Tên | Loại |
|---|---|---|
| **TC-SY-015** | **Kịch bản: Xem health report toàn vault** | System |

| | Chi tiết |
|---|---|
| **Điều kiện tiên quyết** | Vault có ≥5 entries (mix mật khẩu mạnh, yếu, trùng) |
| **Các bước** | 1. Đăng nhập <br> 2. Mở tab Health Check <br> 3. Xem danh sách issues <br> 4. Click từng issue → highlight entry tương ứng |
| **Kết quả mong đợi** | Báo cáo hiển thị đúng số lượng weak/duplicate; click navigate đúng entry |

---

### 4.2. Kịch bản khôi phục

| Mã TC | Tên | Loại |
|---|---|---|
| **TC-SY-005** | **Kịch bản: Quên master password → Dùng recovery key** | System |

| | Chi tiết |
|---|---|
| **Các bước** | 1. Khởi động ứng dụng <br> 2. Nhập sai password → thông báo lỗi <br> 3. Click "Forgot Password" → chọn Recovery Key <br> 4. Nhập recovery key đúng <br> 5. Đặt master password mới <br> 6. Đăng nhập bằng password mới <br> 7. Kiểm tra entries còn nguyên |
| **Kết quả mong đợi** | Recovery thành công; password mới hoạt động; entries không mất |

---

| Mã TC | Tên | Loại |
|---|---|---|
| **TC-SY-006** | **Kịch bản: Quên password → Dùng câu hỏi bí mật** | System |

| | Chi tiết |
|---|---|
| **Điều kiện tiên quyết** | Đã thiết lập câu hỏi bí mật trước đó |
| **Các bước** | 1. Click "Forgot Password" → chọn Secret Questions <br> 2. Trả lời đúng 3 câu hỏi <br> 3. Đặt master password mới <br> 4. Đăng nhập bằng password mới |
| **Kết quả mong đợi** | Khôi phục thành công; entries còn nguyên |

---

| Mã TC | Tên | Loại |
|---|---|---|
| **TC-SY-007** | **Kịch bản: Sai recovery key / sai câu trả lời** | System |

| | Chi tiết |
|---|---|
| **Các bước** | 1. Nhập recovery key sai → kiểm tra thông báo <br> 2. Trả lời sai câu hỏi bí mật → kiểm tra thông báo |
| **Kết quả mong đợi** | Hiển thị thông báo lỗi rõ ràng; không crash; không lộ thông tin |

---

| Mã TC | Tên | Loại |
|---|---|---|
| **TC-SY-016** | **Kịch bản: Recovery → Thiết lập secret questions → Đổi password** | System |

| | Chi tiết |
|---|---|
| **Mô tả** | Kịch bản full recovery lifecycle |
| **Các bước** | 1. Quên password → dùng recovery key khôi phục <br> 2. Đặt master password mới <br> 3. Thiết lập câu hỏi bí mật mới <br> 4. Tắt app → mở lại → đăng nhập bằng password mới <br> 5. Kiểm tra entries còn nguyên |
| **Kết quả mong đợi** | Toàn bộ lifecycle hoạt động trơn tru; dữ liệu persist |

---

### 4.3. Kịch bản bảo mật

| Mã TC | Tên | Loại |
|---|---|---|
| **TC-SY-008** | **Không có file DB trên đĩa** | System |

| | Chi tiết |
|---|---|
| **Các bước** | 1. Tạo vault + thêm entries + tắt app <br> 2. Scan toàn bộ filesystem tìm file "vault.db" hoặc file SQLite <br> 3. Kiểm tra thư mục `~/.shadowvault/` chỉ chứa file PNG |
| **Kết quả mong đợi** | Không tồn tại file DB nào trên đĩa; chỉ có file PNG |

---

| Mã TC | Tên | Loại |
|---|---|---|
| **TC-SY-009** | **Ảnh stego trông giống ảnh bình thường** | System |

| | Chi tiết |
|---|---|
| **Các bước** | 1. Tạo vault với ảnh cover <br> 2. Mở ảnh stego bằng image viewer <br> 3. So sánh thủ công với ảnh gốc |
| **Kết quả mong đợi** | Ảnh stego hiển thị bình thường, không có artifact nhìn thấy được |

---

| Mã TC | Tên | Loại |
|---|---|---|
| **TC-SY-010** | **Decoy images tạo thành công và trông tự nhiên** | System |

| | Chi tiết |
|---|---|
| **Các bước** | 1. Tạo vault lần đầu <br> 2. Kiểm tra thư mục `~/.shadowvault/` <br> 3. Mở từng file ảnh decoy |
| **Kết quả mong đợi** | Có ≥10 ảnh PNG; mỗi ảnh là ảnh thật (không phải gradient); tên file tự nhiên |

---

| Mã TC | Tên | Loại |
|---|---|---|
| **TC-SY-011** | **Đóng app đột ngột → Dữ liệu phiên trước còn nguyên** | System |

| | Chi tiết |
|---|---|
| **Các bước** | 1. Tạo vault + thêm entries <br> 2. Tắt app bình thường (trigger embed_db) <br> 3. Mở lại app → đăng nhập <br> 4. Kiểm tra entries |
| **Kết quả mong đợi** | Entries từ phiên trước còn đầy đủ |

---

| Mã TC | Tên | Loại |
|---|---|---|
| **TC-SY-012** | **Đổi master password → Tắt app → Mở lại** | System |

| | Chi tiết |
|---|---|
| **Các bước** | 1. Đăng nhập → đổi password ("OldPass" → "NewPass") <br> 2. Tắt app <br> 3. Mở lại → đăng nhập bằng "NewPass" |
| **Kết quả mong đợi** | Đăng nhập thành công; entries còn nguyên |

---

| Mã TC | Tên | Loại |
|---|---|---|
| **TC-SY-017** | **Kiểm tra RAM — DEK/KEK không bị swap ra đĩa** | System |

| | Chi tiết |
|---|---|
| **Các bước** | 1. Đăng nhập vault <br> 2. Kiểm tra process memory (dùng task manager hoặc tool phân tích) <br> 3. Tắt app <br> 4. Scan RAM dump tìm chuỗi "SHADOWVAULT_OK_v2" hoặc DEK bytes |
| **Kết quả mong đợi** | Sau khi tắt app, không còn dấu vết khóa mã hóa trong process memory |

---

| Mã TC | Tên | Loại |
|---|---|---|
| **TC-SY-018** | **Thư mục vault trông giống bộ sưu tập ảnh** | System |

| | Chi tiết |
|---|---|
| **Các bước** | 1. Mở file explorer → navigate đến `~/.shadowvault/` <br> 2. Quan sát danh sách file |
| **Kết quả mong đợi** | Chỉ thấy các file PNG có tên tự nhiên (sunset, beach, ...); không có file nào tên đáng ngờ; thumbnail hiển thị ảnh bình thường |

---

| Mã TC | Tên | Loại |
|---|---|---|
| **TC-SY-019** | **Copy password → Clipboard tự động xóa** | System |

| | Chi tiết |
|---|---|
| **Các bước** | 1. Đăng nhập → click "Copy Password" trên một entry <br> 2. Paste ngay → xác nhận password đúng <br> 3. Đợi timeout (nếu có) <br> 4. Paste lại |
| **Kết quả mong đợi** | Bước 2: paste đúng password; Bước 4: clipboard đã bị xóa (nếu có auto-clear) |

---

| Mã TC | Tên | Loại |
|---|---|---|
| **TC-SY-020** | **Ứng dụng hoạt động offline** | System |

| | Chi tiết |
|---|---|
| **Điều kiện tiên quyết** | Vault đã tạo, có ảnh stego + decoy |
| **Các bước** | 1. Tắt kết nối internet <br> 2. Khởi động ứng dụng → đăng nhập <br> 3. Thêm/sửa/xóa entries <br> 4. Tắt app → mở lại |
| **Kết quả mong đợi** | Toàn bộ chức năng hoạt động bình thường; không yêu cầu internet |

---

## 5. Tổng kết Test Cases

| Cấp độ | Số lượng TC | Phạm vi |
|---|---|---|
| **Unit Test** | 60 | 9 modules (bigint, keygen, crypto, steganography, password_gen, schema, vault, recovery, stego_manager) |
| **Integration Test** | 18 | 4 luồng (mã hóa đa tầng, recovery, steganography, health check) |
| **System Test** | 20 | 3 nhóm kịch bản (sử dụng chính, khôi phục, bảo mật) |
| **Tổng cộng** | **98** | |
