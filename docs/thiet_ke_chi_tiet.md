# Tài liệu Thiết kế Chi tiết — ShadowVault

## 1. Tổng quan kiến trúc mã hóa

```
Master Password ──PBKDF2──► KEK ──AES-GCM──► [RSA Private Key]
RSA Private Key  ──RSA──►  DEK
DEK ──AES-GCM──► Vault Entries
```

---

## 2. Các hàm quan trọng

### 2.1. `create_vault` — Tạo Vault mới

**Mục đích:** Khởi tạo vault với hệ thống khóa mã hóa đa tầng và cơ chế recovery.

| | Mô tả |
|---|---|
| **Đầu vào** | `master_password` (chuỗi, ≥8 ký tự); `vault_name` (chuỗi) |
| **Đầu ra** | `dek` (bytes, 32) — khóa mã hóa dữ liệu; `recovery_display` (chuỗi hex) — khóa khôi phục; `vault_id` (số nguyên) |

**Quy trình xử lý:**

1. Sinh DEK (Data Encryption Key) 256-bit bằng bộ sinh số ngẫu nhiên CSPRNG
2. Sinh cặp khóa RSA-2048:
   - Dùng thuật toán Miller-Rabin sinh hai số nguyên tố p, q (1024-bit mỗi số)
   - Tính n = p × q, e = 65537, d = e⁻¹ mod λ(n)
3. Mã hóa DEK bằng RSA public key: `rsa_enc_dek = DEK^e mod n`
4. Sinh salt ngẫu nhiên 32 byte bằng CSPRNG
5. Dẫn xuất KEK từ master password bằng PBKDF2-HMAC-SHA256 (600.000 iterations, salt)
6. Mã hóa RSA private key bằng AES-256-GCM với KEK làm khóa → `kek_enc_rsa_priv`
7. Tạo token xác minh: mã hóa chuỗi cố định bằng AES-256-GCM(KEK) → `verification`
8. Lưu vào CSDL: vault metadata, kek_salt, verification, kek_enc_rsa_priv, rsa_enc_dek
9. Sinh recovery key 128-bit bằng CSPRNG, dẫn xuất KEK phụ từ recovery key (PBKDF2), wrap DEK bằng AES-GCM → lưu vào key_store, trả chuỗi hex cho người dùng

**Các hàm được gọi:**
```
create_vault()
├── generate_dek()           — CSPRNG
├── generate_rsa_keypair()   — Miller-Rabin + BigInt
├── rsa_encrypt_dek()        — RSA
├── generate_salt()          — CSPRNG
├── derive_kek()             — PBKDF2-SHA256
├── wrap_rsa_private()       — AES-256-GCM
├── make_verification()      — AES-256-GCM
└── store_recovery_key()     — CSPRNG + PBKDF2 + AES-256-GCM
```

---

### 2.2. `unlock_vault` — Mở khóa Vault

**Mục đích:** Xác minh master password và trả về DEK để giải mã vault entries.

| | Mô tả |
|---|---|
| **Đầu vào** | `master_password` (chuỗi); `vault_id` (số nguyên, tùy chọn) |
| **Đầu ra** | `dek` (bytes, 32) nếu mật khẩu đúng; `None` nếu sai |

**Quy trình xử lý:**

1. Truy vấn `kek_salt` và `verification` từ bảng `user_auth` trong CSDL
2. Dẫn xuất KEK từ master password + salt bằng PBKDF2-HMAC-SHA256 (600.000 iterations)
3. Xác minh KEK: giải mã verification token bằng AES-256-GCM(KEK), so sánh với plaintext cố định
   - Nếu sai → trả về `None` (mật khẩu không đúng)
4. Truy vấn `kek_enc_rsa_priv` và `rsa_enc_dek` từ bảng `key_store`
5. Giải mã RSA private key: AES-256-GCM decrypt(KEK, kek_enc_rsa_priv) → khôi phục RSAKeyPair
6. Giải mã DEK bằng RSA private key: dùng CRT (Chinese Remainder Theorem) tính m = c^d mod n
7. Kiểm tra DEK có đúng 32 bytes → trả về DEK

**Các hàm được gọi:**
```
unlock_vault()
├── derive_kek()             — PBKDF2-SHA256
├── verify_kek()             — AES-256-GCM
├── unwrap_rsa_private()     — AES-256-GCM
└── rsa_decrypt_dek()        — RSA (CRT optimization)
```

---

### 2.3. `generate_rsa` — Sinh cặp khóa RSA-2048

**Mục đích:** Tạo cặp khóa RSA tự triển khai, không dùng thư viện bên ngoài.

| | Mô tả |
|---|---|
| **Đầu vào** | `bits` (số nguyên, mặc định 2048); `rng` (CSPRNG) |
| **Đầu ra** | RSAKeyPair chứa (n, e, d, p, q) |

**Quy trình xử lý:**

1. Sinh số nguyên tố p có đúng 1024 bit bằng `generate_prime`:
   - Sinh số ngẫu nhiên lẻ 1024-bit (top bit = 1, bottom bit = 1)
   - Loại nhanh bằng trial division (chia cho 60 số nguyên tố nhỏ đầu tiên)
   - Kiểm tra bằng Miller-Rabin (20 vòng, xác suất sai < 10⁻¹²)
   - Lặp lại nếu không đạt, trung bình O(bits) lần thử
2. Sinh số nguyên tố q tương tự, đảm bảo q ≠ p
3. Tính n = p × q (public modulus, 2048-bit)
4. Đặt e = 65537 (public exponent, Fermat F4)
5. Tính λ(n) = lcm(p-1, q-1) bằng công thức (p-1)(q-1) / gcd(p-1, q-1)
6. Kiểm tra gcd(e, λ(n)) = 1 (e và λ(n) nguyên tố cùng nhau)
7. Tính d = e⁻¹ mod λ(n) bằng thuật toán Extended Euclidean (nghịch đảo modular)
8. Xác minh e × d ≡ 1 (mod λ(n)) → trả về RSAKeyPair(n, e, d, p, q)

**Các hàm được gọi:**
```
generate_rsa()
├── generate_prime() [×2]
│     ├── CSPRNG.random_int()
│     └── miller_rabin()
│           └── CSPRNG.random_range_int()
├── BigInt.gcd()
└── BigInt.mod_inverse()    — Extended Euclidean
```

---

### 2.4. `miller_rabin` — Kiểm tra số nguyên tố

**Mục đích:** Kiểm tra xác suất một số lớn có phải số nguyên tố hay không.

| | Mô tả |
|---|---|
| **Đầu vào** | `n` (BigInt) — số cần kiểm tra; `rng` (CSPRNG); `k` (số vòng, mặc định 20) |
| **Đầu ra** | `True` — có thể là số nguyên tố (xác suất sai < 4⁻²⁰); `False` — chắc chắn là hợp số |

**Quy trình xử lý:**

1. Xử lý trường hợp đặc biệt: n < 2 → False; n = 2 hoặc 3 → True; n chẵn → False
2. Trial division: chia n cho 60 số nguyên tố nhỏ (2..283), nếu chia hết → False
3. Phân tích n - 1 = 2^r × d (chia liên tục cho 2 đến khi d lẻ)
4. Lặp k vòng witness:
   - Chọn witness a ngẫu nhiên trong [2, n-2] bằng CSPRNG
   - Tính x = a^d mod n (square-and-multiply modular exponentiation)
   - Nếu x = 1 hoặc x = n-1 → tiếp tục vòng sau (có thể nguyên tố)
   - Lặp r-1 lần: x = x² mod n, nếu x = n-1 → thoát vòng (có thể nguyên tố)
   - Nếu không thoát được → trả False (chắc chắn hợp số)
5. Nếu qua hết k vòng → trả True (có thể nguyên tố)

---

### 2.5. `generate_prime` — Sinh số nguyên tố lớn

**Mục đích:** Sinh số nguyên tố ngẫu nhiên có đúng n bit, phục vụ cho việc tạo cặp khóa RSA.

| | Mô tả |
|---|---|
| **Đầu vào** | `bits` (số nguyên, ≥8) — số bit yêu cầu; `rng` (CSPRNG); `miller_rabin_rounds` (mặc định 20) |
| **Đầu ra** | BigInt — số nguyên tố có đúng `bits` bit |
| **Thuật toán** | Generate-and-test: CSPRNG + Trial Division + Miller-Rabin |

**Quy trình xử lý:**

1. Sinh số ngẫu nhiên `bits` bit bằng CSPRNG
2. Đặt bit cao nhất = 1 (đảm bảo đúng `bits` bit) và bit thấp nhất = 1 (đảm bảo lẻ)
3. Trial division: chia thử cho 60 số nguyên tố nhỏ đầu tiên (2..283)
   - Nếu candidate chia hết cho bất kỳ số nào → loại, quay lại bước 1
   - Nếu candidate chính là một trong các số nguyên tố nhỏ → trả về ngay
4. Kiểm tra bằng Miller-Rabin (20 vòng, xác suất sai < 10⁻¹²)
   - Nếu không đạt → quay lại bước 1
   - Nếu đạt → trả về candidate
5. Số lần thử trung bình: O(bits) theo định lý số nguyên tố (mật độ số nguyên tố gần 2^bits ≈ 1 / (bits × ln2))

---

### 2.6. Class `BigInt` — Số nguyên lớn tự triển khai

**Mục đích:** Cung cấp phép toán số nguyên lớn (arbitrary-precision) cho RSA, không dùng thư viện bên ngoài.

| | Mô tả |
|---|---|
| **Biểu diễn nội bộ** | Mảng các word 32-bit unsigned, thứ tự little-endian (index 0 = word thấp nhất). BASE = 2³² |
| **Phạm vi** | Số nguyên không âm, kích thước tùy ý |

**Các phép toán và thuật toán:**

**Phép cộng (`__add__`):**
1. Duyệt từng cặp word (a[i], b[i]) từ word thấp → cao
2. Tính tổng s = a[i] + b[i] + carry
3. Kết quả word = s & 0xFFFFFFFF, carry = s >> 32
4. Nếu còn carry sau word cuối → thêm word mới

**Phép trừ (`__sub__`, yêu cầu self ≥ other):**
1. Duyệt từng cặp word, tính diff = a[i] - b[i] - borrow
2. Nếu diff < 0: diff += BASE, borrow = 1
3. Loại bỏ các word 0 ở đầu (trim)

**Phép nhân (`__mul__`, schoolbook O(n²)):**
1. Tạo buffer kết quả kích thước n + m words
2. Hai vòng lặp lồng nhau: buf[i+j] += a[i] × b[j] + carry
3. Mỗi tích a[i] × b[j] có thể đến 64-bit, tách carry = t >> 32

**Phép chia / Modulo (`_divmod`, Long Division):**
1. Nếu divisor chỉ có 1 word → dùng fast path (chia đơn giản)
2. Normalize: dịch trái cả dividend và divisor sao cho MSW của divisor ≥ BASE/2
3. Ước lượng thương từng digit: q̂ = (u[j+n] × BASE + u[j+n-1]) / v[n-1]
4. Nhân và trừ: u[j..j+n] -= q̂ × v, nếu trừ quá → cộng lại (add-back)
5. Un-normalize remainder bằng dịch phải
6. Thuật toán tương tự Algorithm D trong Knuth TAOCP vol.2 §4.3.1

**Lũy thừa modular (`pow_mod`, square-and-multiply):**
1. Tính self^exp mod mod
2. Duyệt từng bit của exp từ cao → thấp: result = result² mod m, nếu bit = 1: result = result × base mod m
3. Dùng cho RSA encryption/decryption (c = m^e mod n, m = c^d mod n)

**GCD (`gcd`, thuật toán Euclid):**
1. gcd(a, 0) = a
2. gcd(a, b) = gcd(b, a mod b)
3. Lặp cho đến khi b = 0 → trả a

**Nghịch đảo modular (`mod_inverse`, Extended Euclidean):**
1. Tìm x sao cho self × x ≡ 1 (mod m)
2. Duy trì: old_r = old_s × a + old_t × m
3. Khi old_r = 1 → old_s là nghịch đảo
4. Nếu gcd ≠ 1 → nghịch đảo không tồn tại, raise lỗi
5. Dùng để tính private exponent d = e⁻¹ mod λ(n) trong RSA

---

### 2.7. `hide` — Nhúng dữ liệu vào ảnh (LSB Steganography)

**Mục đích:** Giấu dữ liệu nhị phân vào ảnh PNG bằng kỹ thuật thay thế bit thấp nhất.

| | Mô tả |
|---|---|
| **Đầu vào** | `cover_path` (đường dẫn ảnh gốc PNG); `payload` (bytes, ≤10MB); `output_path` (đường dẫn đầu ra) |
| **Đầu ra** | File PNG stego tại output_path |

**Quy trình xử lý:**

1. Kiểm tra payload không vượt 10MB
2. Mở ảnh gốc, convert sang RGB, tính capacity = (width × height × 3) / 8 bytes
3. Tạo full payload: magic header "SVLT" (4 bytes) ∥ payload length (4 bytes, big-endian) ∥ payload
4. Kiểm tra capacity ≥ kích thước full payload
5. Chuyển full payload thành bit stream (mỗi byte → 8 bit, MSB trước)
6. Duyệt từng pixel, thay thế LSB (bit thấp nhất) của kênh R, G, B:
   - R = (R & 0xFE) | bit[i]
   - G = (G & 0xFE) | bit[i+1]
   - B = (B & 0xFE) | bit[i+2]
   - Mỗi pixel chứa 3 bit dữ liệu
7. Lưu ảnh kết quả dạng PNG (compress_level=1)

---

### 2.8. `unhide` — Trích xuất dữ liệu từ ảnh stego

**Mục đích:** Đọc dữ liệu ẩn từ ảnh stego PNG đã được tạo bởi `hide`.

| | Mô tả |
|---|---|
| **Đầu vào** | `stego_path` (đường dẫn ảnh stego PNG) |
| **Đầu ra** | `payload` (bytes) — dữ liệu gốc đã nhúng |

**Quy trình xử lý:**

1. Mở ảnh stego, convert sang RGB
2. Trích xuất LSB từ từng kênh R, G, B của tất cả pixel → thu được bit stream
3. Chuyển bit stream thành byte stream (mỗi 8 bit → 1 byte)
4. Kiểm tra 4 byte đầu = magic "SVLT", nếu không → báo lỗi
5. Đọc 4 byte tiếp theo → payload length (big-endian uint32)
6. Trích payload từ vị trí byte thứ 8, đúng length byte → trả về

---

### 2.9. `extract_db` / `embed_db` — Vòng đời Steganography

**Mục đích:** Quản lý việc trích xuất DB từ ảnh stego khi khởi động và nhúng DB lại khi tắt ứng dụng.

**`extract_db` (Startup):**

| | Mô tả |
|---|---|
| **Đầu vào** | Không (tự scan folder ~/.shadowvault/) |
| **Đầu ra** | Không (side effect: DB được load vào SQLite in-memory) |

1. Scan tất cả file PNG trong `~/.shadowvault/`, kiểm tra magic header "SVLT" bằng `peek_magic` (chỉ đọc 11 pixel đầu)
2. Gọi `unhide()` trích xuất compressed payload từ ảnh stego tìm được
3. Giải nén payload bằng gzip decompress
4. Gọi `load_db_from_bytes()` nạp dữ liệu vào SQLite in-memory (thay thế toàn bộ DB hiện tại)

**`embed_db` (Shutdown):**

| | Mô tả |
|---|---|
| **Đầu vào** | Không |
| **Đầu ra** | Không (side effect: DB được nhúng lại vào ảnh stego) |

1. Gọi `dump_db_to_bytes()` serialize toàn bộ SQLite in-memory ra bytes
2. Nén bằng gzip compress (level 9, nén tối đa)
3. Kiểm tra ảnh stego đủ capacity chứa dữ liệu nén
4. Gọi `hide()` ghi đè LSB của ảnh stego bằng dữ liệu mới

**Các hàm được gọi:**
```
extract_db()                    embed_db()
├── find_stego_image()          ├── find_stego_image()
│     └── peek_magic()          ├── dump_db_to_bytes()
├── unhide()                    ├── gzip.compress()
├── gzip.decompress()           └── hide()
└── load_db_from_bytes()
```

---

### 2.10. `unlock_with_recovery_key` — Mở khóa bằng Recovery Key

**Mục đích:** Khôi phục DEK khi người dùng quên master password, sử dụng Emergency Recovery Key.

| | Mô tả |
|---|---|
| **Đầu vào** | `recovery_display` (chuỗi hex, VD: "A1B2C3D4-E5F6G7H8-..."); `vault_id` (số nguyên) |
| **Đầu ra** | `dek` (bytes, 32) nếu recovery key đúng; `None` nếu sai |

**Quy trình xử lý:**

1. Parse chuỗi hex: loại bỏ dấu "-" và khoảng trắng → chuyển 32 ký tự hex thành 16 bytes
2. Truy vấn `recovery_enc_dek` từ bảng `key_store` (blob = salt (32B) ∥ enc_dek)
3. Tách salt (32 bytes đầu) và enc_dek (phần còn lại) từ blob
4. Dẫn xuất KEK phụ từ recovery key + salt bằng PBKDF2-SHA256
5. Unwrap DEK: giải mã enc_dek bằng AES-256-GCM(KEK phụ)
   - Nếu tag xác minh sai (recovery key không đúng) → trả `None`
   - Nếu thành công → trả DEK

---

### 2.11. `save_secret_questions` / `unlock_with_secret_questions` — Câu hỏi bí mật

**Mục đích:** Cung cấp phương thức khôi phục thứ hai thông qua câu hỏi bí mật do người dùng tự đặt.

**`save_secret_questions`:**

| | Mô tả |
|---|---|
| **Đầu vào** | `dek` (bytes); `questions_answers` (danh sách ≥3 cặp câu hỏi/trả lời) |
| **Đầu ra** | `True` nếu thành công |

1. Nối tất cả câu trả lời (lowercase, strip) bằng ký tự "|" → encode UTF-8
2. Sinh salt ngẫu nhiên 32 byte, dẫn xuất KEK từ chuỗi nối (PBKDF2-SHA256)
3. Wrap DEK bằng AES-256-GCM(KEK) → lưu blob [salt ∥ enc_dek] vào `key_store.questions_enc_dek`
4. Với từng câu hỏi: hash câu trả lời riêng lẻ (PBKDF2 + salt riêng) → lưu vào bảng `secret_question`

**`unlock_with_secret_questions`:**

| | Mô tả |
|---|---|
| **Đầu vào** | `answers` (danh sách câu trả lời, đúng thứ tự) |
| **Đầu ra** | `dek` (bytes) hoặc `None` |

1. Nối câu trả lời (lowercase, strip) bằng "|" → encode UTF-8
2. Tách salt và enc_dek từ blob `questions_enc_dek` trong `key_store`
3. Dẫn xuất KEK từ chuỗi nối + salt (PBKDF2) → unwrap DEK bằng AES-GCM
4. Nếu tag AES-GCM sai → `None`; đúng → trả DEK

---

### 2.12. `derive_kek` — Dẫn xuất KEK từ mật khẩu

**Mục đích:** Chuyển đổi master password thành khóa mã hóa 256-bit, chống brute-force bằng số vòng lặp cao.

| | Mô tả |
|---|---|
| **Đầu vào** | `password` (chuỗi hoặc bytes); `salt` (bytes, 32) |
| **Đầu ra** | `kek` (bytes, 32) — Key Encryption Key 256-bit |
| **Thuật toán** | PBKDF2-HMAC-SHA256, 600.000 iterations |

**Quy trình xử lý:**

1. Encode password sang UTF-8 nếu là chuỗi
2. Áp dụng PBKDF2 với hàm HMAC-SHA256, salt, 600.000 iterations → 32 bytes
3. KEK không bao giờ được lưu trữ — chỉ tồn tại trong RAM khi cần

---

### 2.13. `aes_encrypt` / `aes_decrypt` — Mã hóa/Giải mã đối xứng

**Mục đích:** Authenticated encryption cho toàn bộ hệ thống.

**`aes_encrypt`:**

| | Mô tả |
|---|---|
| **Đầu vào** | `key` (bytes, 32); `plaintext` (bytes) |
| **Đầu ra** | `blob` = nonce (12B) ∥ ciphertext ∥ auth tag (16B) |
| **Thuật toán** | AES-256-GCM |

1. Sinh nonce 12 bytes bằng CSPRNG
2. Mã hóa AES-256-GCM(key, nonce, plaintext) → ciphertext + tag
3. Nối nonce ∥ ciphertext ∥ tag → trả blob

**`aes_decrypt`:**

| | Mô tả |
|---|---|
| **Đầu vào** | `key` (bytes, 32); `data` (bytes) — blob từ `aes_encrypt` |
| **Đầu ra** | `plaintext` (bytes); raise `InvalidTag` nếu key sai hoặc dữ liệu bị sửa |

1. Tách nonce (12B đầu) và ciphertext+tag (phần còn lại)
2. Giải mã AES-256-GCM, xác minh tag toàn vẹn
3. Tag sai → raise lỗi; đúng → trả plaintext

---

### 2.14. Class `CSPRNG` — Bộ sinh số ngẫu nhiên an toàn

**Mục đích:** Nguồn ngẫu nhiên an toàn mật mã tự triển khai cho toàn hệ thống.

| | Mô tả |
|---|---|
| **Khởi tạo** | Seed 64 bytes từ `os.urandom` (true entropy) |
| **Thuật toán** | Hash-based DRBG, tương tự NIST SP 800-90A |

**Quy trình sinh block:**

1. Tạo input: seed (64B) ∥ counter (8B big-endian) ∥ extra entropy OS (8B)
2. Hash SHA-256 → 32 bytes ngẫu nhiên
3. Tăng counter, cập nhật seed = SHA-256(seed ∥ counter) — chống state recovery
4. Lặp nếu cần thêm bytes, cắt đúng kích thước yêu cầu

**Phương thức:** `random_bytes(n)`, `random_int(bits)`, `random_bigint_exact(bits)`, `random_range_int(low, high)`

---

### 2.15. `add_entry` / `get_all_entries` — CRUD Entry

**`add_entry`:**

| | Mô tả |
|---|---|
| **Đầu vào** | `dek` (bytes, 32); `entry` (VaultEntry — title, url, username, password, notes) |
| **Đầu ra** | `entry_id` (số nguyên) |

1. Mã hóa url, username, password, notes bằng AES-256-GCM(DEK)
2. Title giữ plaintext (cho phép tìm kiếm không cần giải mã)
3. INSERT vào `vault_entry` → trả entry_id

**`get_all_entries`:**

| | Mô tả |
|---|---|
| **Đầu vào** | `dek` (bytes, 32); `search` (chuỗi, tùy chọn); `vault_id` (tùy chọn) |
| **Đầu ra** | Danh sách VaultEntry đã giải mã |

1. SELECT từ `vault_entry`, giải mã từng trường bằng AES-256-GCM(DEK)
2. Entry giải mã thất bại → bỏ qua
3. Lọc theo search keyword (nếu có) → trả danh sách

---

### 2.16. `change_master_password` — Đổi mật khẩu chủ

**Mục đích:** Đổi master password mà không cần mã hóa lại vault entries.

| | Mô tả |
|---|---|
| **Đầu vào** | `dek` (bytes, 32); `new_password` (chuỗi); `vault_id` (số nguyên) |
| **Đầu ra** | `True` nếu thành công |

**Quy trình xử lý:**

1. Sinh cặp RSA-2048 mới → mã hóa DEK (không đổi) bằng public key mới
2. Sinh salt mới, dẫn xuất KEK mới từ new_password (PBKDF2)
3. Mã hóa RSA private key mới bằng AES-256-GCM(KEK mới), tạo verification mới
4. UPDATE `user_auth` và `key_store` — DEK và vault entries không bị ảnh hưởng

---

### 2.17. `generate_password` — Sinh mật khẩu ngẫu nhiên

| | Mô tả |
|---|---|
| **Đầu vào** | `length` (mặc định 20); `use_upper/lower/digits/symbols` (bool); `exclude_ambiguous` (bool) |
| **Đầu ra** | Chuỗi mật khẩu ngẫu nhiên |
| **Thuật toán** | `secrets.choice()` — CSPRNG cấp OS |

**Quy trình xử lý:**

1. Xây charset từ các tùy chọn; loại ký tự nhầm (l, O, 0, 1, I) nếu exclude_ambiguous
2. Đảm bảo ≥1 ký tự mỗi loại charset → sinh phần còn lại bằng `secrets.choice()`
3. Trộn ngẫu nhiên vị trí bằng `secrets.SystemRandom().shuffle()` → trả chuỗi

---

### 2.18. `check_all_health` — Kiểm tra sức khỏe vault

| | Mô tả |
|---|---|
| **Đầu vào** | `entries` (danh sách VaultEntry đã giải mã) |
| **Đầu ra** | Danh sách HealthIssue (entry_id, issue_type: "weak"/"duplicate", detail) |
| **Thuật toán** | zxcvbn + Shannon Entropy |

**Quy trình xử lý:**

1. Duyệt từng entry → `check_strength()`: tính entropy, score zxcvbn → nếu score < 2: "weak"
2. Theo dõi map password → entries → nếu ≥2 entry cùng password: "duplicate"
3. Trả danh sách issues

---

### 2.19. `load_db_from_bytes` / `dump_db_to_bytes` — Serialize CSDL

**Mục đích:** Chuyển đổi CSDL in-memory sang/từ bytes để nhúng vào ảnh stego.

**`load_db_from_bytes`:**

| | Mô tả |
|---|---|
| **Đầu vào** | `data` (bytes) — CSDL đã serialize |
| **Đầu ra** | Không (thay thế toàn bộ CSDL in-memory) |

1. `sqlite3.Connection.deserialize(data)` — nạp binary vào in-memory connection
2. Áp dụng lại row_factory và PRAGMA foreign_keys

**`dump_db_to_bytes`:**

| | Mô tả |
|---|---|
| **Đầu vào** | Không |
| **Đầu ra** | `data` (bytes) — toàn bộ CSDL dạng binary |

1. `sqlite3.Connection.serialize()` — xuất DB thành bytes cho gzip + stego

---

## 3. Sơ đồ quan hệ gọi hàm tổng thể

```
[Khởi động]
main() → extract_db()
           ├── find_stego_image() → peek_magic()
           ├── unhide()
           ├── gzip.decompress()
           └── load_db_from_bytes()

[Tạo Vault lần đầu]
_do_create()
  ├── create_vault()
  │     ├── generate_dek()
  │     ├── generate_rsa_keypair() → generate_rsa()
  │     │     ├── generate_prime() → miller_rabin()
  │     │     └── BigInt.mod_inverse()
  │     ├── rsa_encrypt_dek()
  │     ├── derive_kek()
  │     ├── wrap_rsa_private() → aes_encrypt()
  │     ├── make_verification() → aes_encrypt()
  │     └── store_recovery_key()
  ├── first_embed()
  │     ├── setup_cover()
  │     ├── dump_db_to_bytes() → gzip.compress() → hide()
  └── populate_decoys()

[Mở khóa Vault]
_do_unlock() → unlock_vault()
                ├── derive_kek()
                ├── verify_kek() → aes_decrypt()
                ├── unwrap_rsa_private() → aes_decrypt()
                └── rsa_decrypt_dek() → RSAKeyPair.decrypt()

[Thêm/Sửa/Xem Entry]
add_entry()        → encrypt_field() → aes_encrypt()
update_entry()     → encrypt_field() → aes_encrypt()
get_all_entries()  → decrypt_field() → aes_decrypt()

[Tắt ứng dụng]
on_quit() → embed_db()
              ├── dump_db_to_bytes()
              ├── gzip.compress()
              └── hide()
```
