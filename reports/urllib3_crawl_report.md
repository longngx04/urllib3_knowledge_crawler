# urllib3 Security Knowledge Crawl Report

**Phiên bản dữ liệu:** crawl live ngày 04/08/2026 (`./data`)  
**Trạng thái:** pipeline end-to-end đã chạy thành công trên dữ liệu thật

---

## 1. Tổng quan

Dự án xây dựng cơ sở tri thức bảo mật theo phiên bản (version-aware) cho thư viện
[`urllib3`](https://github.com/urllib3/urllib3), phục vụ hệ thống **SAST AI-assisted**.

Mục tiêu không dừng ở mức SCA — tức trả lời “phiên bản đang dùng có nằm trong khoảng bị ảnh
hưởng hay không” — mà nhằm cung cấp đủ điều kiện để SAST đánh giá: *mã nguồn ứng dụng có thực
sự chạm tới API, cấu hình và luồng dữ liệu khiến lỗ hổng trở nên khai thác được*, và khi nào
một phát hiện nên được loại trừ vì dương tính giả.

Pipeline giữ nguyên byte gốc từ upstream kèm băm SHA-256 (provenance), chuẩn hoá thành bản ghi
có kiểu, hợp nhất alias advisory, chiếu khoảng bị ảnh hưởng lên danh mục phát hành PyPI, bổ
sung bằng chứng patch và regression test, sinh security pattern định hướng SAST cùng tài liệu
truy hồi (retrieval), cuối cùng validate và xuất thống kê có thể tái lập.

### Kết quả crawl live (đã kiểm chứng)


| Hạng mục                            | Kết quả                           |
| ----------------------------------- | --------------------------------- |
| Phiên bản `urllib3` trong danh mục  | **108** (4 prerelease, 4 bị yank) |
| Advisory sau khi hợp nhất alias     | **19**                            |
| Alias liên kết (CVE / GHSA / PYSEC) | **57**                            |
| Bản ghi patch có bằng chứng diff    | **21**                            |
| Security pattern cho SAST           | **19**                            |
| Tài liệu KB phục vụ truy hồi        | **92**                            |
| Độ phủ provenance                   | **1.00**                          |
| Tỷ lệ hợp lệ theo schema            | **1.00**                          |


```bash
python -m crawler run --config configs/urllib3.yaml --output data
```

**Đánh giá nhanh:** pipeline vận hành trọn vẹn trên dữ liệu thật; mọi claim bảo mật đều kèm provenance; output đủ để engine SAST phán quyết theo *version ∧ API ∧ cấu hình ∧ luồng dữ liệu*
thay vì chỉ so phiên bản. Đồng thời, lần chạy live đã phát hiện **3 lỗi thực thi** (đã khắc
phục) và **3 hạn chế chất lượng dữ liệu còn tồn tại** — trong đó nghiêm trọng nhất là khoảng
OSV loại `GIT` mở làm phình tập phiên bản bị ảnh hưởng ở tầng advisory. Chi tiết tại mục 12
và 13.

---

## 2.  Bối cảnh vấn đề

Feed SCA tiêu chuẩn cung cấp mã định danh, mô tả, khoảng bị ảnh hưởng, phiên bản đã sửa và
mức nghiêm trọng. Thông tin này cần thiết nhưng chưa đủ cho SAST, vì còn thiếu bốn khả năng
sau:


| Hạn chế của SCA thuần version             | Hệ quả vận hành                                                |
| ----------------------------------------- | -------------------------------------------------------------- |
| Không xét điều kiện sử dụng API           | Cảnh báo thừa trên code không gọi symbol liên quan             |
| Không mô tả tiền đề cấu hình / data-flow  | Bỏ sót trường hợp lỗ hổng chỉ phát tác khi cấu hình rủi ro     |
| Thiếu bằng chứng patch và regression test | Khuyến nghị nâng cấp khó kiểm chứng được                       |
| Thiếu provenance                          | Hệ thống AI không phân biệt được sự thật có nguồn với suy đoán |


---

## 3. Lý do chọn `urllib3` làm package pilot

1. **Tính phổ biến.** `urllib3` là nền tảng của `requests` và phần lớn stack HTTP Python; tri
  thức thu được có giá trị áp dụng ngay.
2. **Bằng chứng công khai đầy đủ.** PyPI JSON, GitHub tags/releases/changelog/commits, OSV và
  GHSA đều truy cập được mà không phụ thuộc feed thương mại.
3. **Đa dạng lớp phát hiện.** Các lỗ hổng trải đủ API misuse, cấu hình TLS/proxy và tiền đề
  data-flow qua redirect. Lần crawl live sinh đủ bốn loại `detection_type` (mục 11).
4. **Đo lường trung thực.** Một package PEP 440 trưởng thành giúp các chỉ số độ phủ không bị
  pha loãng bởi nhiều lược đồ version khác nhau.
5. **Kiến trúc tái sử dụng.** Định danh package nằm trong `configs/urllib3.yaml`; không
  hardcode sự thật bảo mật của `urllib3` vào logic lõi.

---

## 4. Phạm vi thực hiện

### Trong phạm vi (Phase 0–13)

Bootstrap CLI, hợp đồng dữ liệu, tầng HTTP an toàn có cache, danh mục phiên bản PyPI, dữ liệu
GitHub release/tag/changelog, advisory OSV kèm hợp nhất alias, giải khoảng bị ảnh hưởng, bổ
sung patch và regression test, sinh security pattern, xuất tài liệu KB, validate + thống kê,
pipeline CLI đầy đủ kèm lệnh `query`, bảo đảm tính tái lập, và báo cáo này.

### Ngoài phạm vi

Engine SAST hoàn chỉnh; vector database; crawl toàn bộ issue/PR; coi blog hoặc bản nháp LLM
là nguồn có thẩm quyền cho khoảng bị ảnh hưởng; hỗ trợ production đa package; sinh mã khai
thác. Nhánh NVD giữ ở mức tuỳ chọn, không nằm trong đường chạy mặc định.

---

## 5. Yêu cầu tri thức cho SAST 


| Câu hỏi của engine SAST                    | Artifact trả lời                                    |
| ------------------------------------------ | --------------------------------------------------- |
| Thư viện có những phiên bản nào?           | `data/normalized/versions.jsonl`                    |
| Có advisory nào và alias tương ứng?        | `data/normalized/advisories.jsonl` + alias resolver |
| Chính xác phiên bản nào bị ảnh hưởng?      | `affected_ranges[].resolved` (range resolver)       |
| Symbol, cấu hình, luồng dữ liệu liên quan? | `data/normalized/security_patterns.jsonl`           |
| Khi nào code được coi là an toàn?          | `negative_conditions` trong security pattern        |
| Patch và test chứng minh bản sửa?          | `data/normalized/patches.jsonl`                     |
| Nội dung phục vụ truy hồi cho LLM?         | `data/kb/documents.jsonl`                           |
| Mức độ tin cậy của claim?                  | `provenance` trên từng bản ghi + `data/stats.json`  |


---

## 6. Đánh giá nguồn dữ liệu


| Nguồn                                             | Hạng     | Vai trò                                            |
| ------------------------------------------------- | -------- | -------------------------------------------------- |
| GHSA / ghi chú bảo mật của maintainer             | 1        | Hành vi kỹ thuật, tiền đề, khuyến nghị khắc phục   |
| Tag, commit, test, changelog trên repo chính thức | 1        | Bằng chứng patch, symbol thay đổi, regression test |
| PyPI project JSON                                 | 1        | Danh mục phát hành, ngày upload, trạng thái yank   |
| OSV                                               | 1        | Alias, khoảng bị ảnh hưởng, mức nghiêm trọng       |
| NVD                                               | Tuỳ chọn | Bổ sung CWE/CVSS (chưa bật mặc định)               |


**Nguyên tắc xử lý xung đột:** nguồn hạng thấp không được ghi đè âm thầm nguồn hạng cao. Khi
hai nguồn mâu thuẫn, cả hai claim được giữ kèm lý do thay vì chọn một và xoá dấu vết.

---

## 7. Pipeline Architecture

```text
configs/urllib3.yaml
  → RetrievalClient + RawStore     (timeout, retry, giới hạn kích thước, cache SHA-256)
  → adapter PyPI / GitHub / OSV
  → normalizer + alias resolver + range resolver
  → patch enrichment + security pattern + KB documents
  → validate → stats.json / manifest.json
```

### Trình tự vận hành

1. Nạp `configs/urllib3.yaml` (không chứa secret; token đọc từ `.env` hoặc biến môi trường).
2. Thu thập các nguồn được bật; lưu body gốc và metadata trong allowlist vào `data/raw/`. Lần
  crawl live tạo **27 response gốc (~1,7 MB)**. Cache địa chỉ hoá theo SHA-256 cho phép chạy
   lại bằng `--skip-crawl` mà không gọi mạng.
3. Chuẩn hoá thành model Pydantic Phase 1; mỗi bản ghi kèm provenance (`source_type`,
  `source_id`, `raw_sha256`, `retrieved_at`, `extractor_version`).
4. Hợp nhất alias theo thứ tự ưu tiên **GHSA > CVE > OSV/PYSEC**, rồi chiếu khoảng bị ảnh
  hưởng lên danh mục phiên bản PyPI.
5. Tải commit từ URL vá trong advisory; phân tích diff để rút file, symbol, guard mới và
  regression test.
6. Sinh security pattern và tài liệu KB từ bằng chứng đã thu thập.
7. Validate và xuất `stats.json`, `manifest.json`, `validation_errors.json`.

Chế độ offline phục vụ payload fixture qua `httpx.MockTransport` nhưng vẫn thực thi logic dựng
URL và đường đi cache — bảo đảm kiểm chứng pipeline trong CI mà không phụ thuộc mạng.

---

## 8. Thiết kế schema

Sáu họ bản ghi: `version`, `advisory`, `patch`, `security_pattern`, `kb_document`, và
`provenance` dùng chung. Schema JSON Draft 2020-12 trong `schemas/` đồng bộ với model Pydantic.

Hai quy ước bắt buộc: giá trị chưa biết để `null` (không điền mặc định giả); so sánh phiên bản
luôn qua `packaging.version.Version`, không so chuỗi.

---

## 9. Giải phiên bản và alias

- Mọi release PyPI phân tích được đều chuẩn hoá theo PEP 440; khoá không hợp lệ được báo cáo,
không bị bỏ âm thầm.
- Alias chỉ liên kết khi nguồn nêu tường minh; cụm mơ hồ được báo cáo.
- Khoảng bị ảnh hưởng dựng từ `events` OSV và specifier PEP 440; sentinel `0` nghĩa là “từ đầu
lịch sử”; **không suy diễn phiên bản đã sửa** khi nguồn không nêu.

### Kết quả live


| Chỉ số                  | Giá trị | Diễn giải                                                                                        |
| ----------------------- | ------- | ------------------------------------------------------------------------------------------------ |
| `alias_resolution_rate` | 1.00    | 57 alias, không cụm mơ hồ                                                                        |
| `version_coverage`      | 0.907   | 98/108 phiên bản khớp tag Git hoặc commit; phần còn lại là release rất cũ không có tag tương ứng |


---

## 10. Bổ sung bằng chứng patch

21 bản ghi patch được dựng từ commit chính thức. Mỗi bản ghi gồm `commit_sha`, `parent_sha`,
danh sách file/symbol thay đổi, guard mới thêm và regression test liên quan.


| Chỉ số                            | Giá trị |
| --------------------------------- | ------- |
| `patch_resolution_rate`           | 1.00    |
| `fixed_release_verification_rate` | 1.00    |


Mọi phiên bản được nêu là “đã sửa” đều tồn tại trong danh mục PyPI.

### Ví dụ — CVE-2023-43804 (`GHSA-v845-jxx5-vc9f`)

Commit: `01220354d389cd05474713f8c982d05c9b17aafb`

```text
changed_files:  src/urllib3/util/retry.py, test/test_retry.py,
                test/with_dummyserver/test_poolmanager.py, CHANGES.rst
added_guards:   assert retry.remove_headers_on_redirect == {"authorization", "cookie"}
                assert "Cookie" not in data
fixed_versions: 1.26.17, 2.0.6
confidence:     0.95 — official repository commit with extracted diff evidence
```

Các guard trích từ diff giúp phân biệt “đã nâng version” với “đã thực sự đóng lỗ hổng”, vì
chúng chỉ ra hành vi nào được kiểm tra sau bản sửa.

---

## 11. Sinh security pattern

Thứ tự ưu tiên bằng chứng: khoảng có cấu trúc → văn bản advisory → diff patch → regression
test → changelog. Suy luận thiếu bằng chứng được ghi rõ trong `confidence.rationale`. Bản nháp
LLM (nếu bổ sung sau này) **không được phép** thay đổi khoảng bị ảnh hưởng có thẩm quyền.

### Phân bố 19 pattern theo lớp phát hiện


| `detection_type`                     | Số lượng | Điều kiện phán quyết SAST                             |
| ------------------------------------ | -------- | ----------------------------------------------------- |
| `version_api_dataflow`               | 10       | version ∧ gọi API ∧ luồng dữ liệu không tin cậy       |
| `version_api`                        | 4        | version ∧ gọi API liên quan                           |
| `version_api_configuration_dataflow` | 2        | thêm điều kiện cấu hình rủi ro                        |
| `version_only`                       | 3        | chưa rút được điều kiện sử dụng — chỉ phù hợp mức SCA |


**Mức nghiêm trọng:** 1 CRITICAL · 9 HIGH · 9 MODERATE  
**Điểm hữu dụng SAST trung bình:** `average_sast_usefulness_score` = **0.816**

Ba pattern `version_only` là nguyên nhân chính kéo điểm xuống: advisory tương ứng không kèm
commit vá nên không rút được symbol.

---

## 12. Kết quả validate và phát hiện bất nhất

Bước validate kiểm tra schema, provenance, advisory canonical trùng lặp và tín hiệu bất nhất.
Mọi lỗi kèm `record_id` và lý do; chế độ strict trả exit code 1.

### Chỉ số live


| Chỉ số                            | Giá trị   | Nhận xét                                     |
| --------------------------------- | --------- | -------------------------------------------- |
| `provenance_coverage`             | 1.000     | Mọi bản ghi đều truy nguyên được về byte gốc |
| `schema_validation_rate`          | 1.000     | Không bản ghi lệch schema                    |
| `duplicate_rate`                  | 0.000     | Không advisory canonical trùng               |
| `alias_resolution_rate`           | 1.000     | 57 alias, không cụm mơ hồ                    |
| `patch_resolution_rate`           | 1.000     | 21/21 patch có bằng chứng diff               |
| `fixed_release_verification_rate` | 1.000     | Phiên bản “đã sửa” đều tồn tại trên PyPI     |
| `version_coverage`                | 0.907     | 98/108 phiên bản khớp tag/commit             |
| `range_resolution_rate`           | **0.632** | 7/19 advisory có khoảng bất nhất             |
| `average_sast_usefulness_score`   | 0.816     | Bị kéo xuống bởi 3 pattern `version_only`    |


### Phân tích 7 lỗi `contradictory_ranges`

Cả 7 lỗi cùng một dạng: phiên bản được advisory nêu là “đã sửa” vẫn xuất hiện trong tập
phiên bản bị ảnh hưởng. Ví dụ CVE-2023-45803 (`GHSA-g4mx-q9vg-27p4`): `1.26.18` và `2.0.7`
vừa là fixed version vừa nằm trong `affected_versions`.

**Nguyên nhân đã xác định:** advisory OSV kèm khoảng loại `GIT` chỉ có sự kiện
`introduced: "0"` mà không có `fixed`. Khi resolver chiếu khoảng này lên danh mục PyPI, toàn
bộ 108 phiên bản bị khớp; phép hợp ở tầng advisory kéo theo cả các phiên bản đã sửa.

**Phạm vi ảnh hưởng:** các khoảng `ECOSYSTEM` bên trong vẫn đúng. Với CVE-2023-45803,
`affected_ranges[].resolved` nêu chính xác `2.0.0`–`2.0.6` và `0.2`–`1.26.17`. Sai lệch nằm ở
trường tổng hợp `advisory.affected_versions`. Trường `security_pattern.version.resolved` —
thứ mà lệnh `query` sử dụng — vẫn cho kết quả đúng (ví dụ truy vấn `2.4.0` với CVE-2024-37891
trả về `Affected: no`).

**Ý nghĩa quản trị:** đây là tín hiệu dữ liệu xấu nhưng tín hiệu hệ thống tốt — tầng validate
chỉ đúng chỗ cần sửa thay vì để lỗi âm thầm đi vào phán quyết SAST.

---

## 13. Sự cố phát sinh khi crawl live và trạng thái khắc phục

Ba lỗi chỉ lộ khi gặp dữ liệu thật. Cả ba đã được sửa kèm test hồi quy
([PR #13](https://github.com/longngx04/urllib3_knowledge_crawler/pull/13)).


| Sự cố                                      | Hệ quả                                                | Cách khắc phục                                                                                                                                              |
| ------------------------------------------ | ----------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------- |
| CLI không nạp `.env` (chỉ đọc `os.getenv`) | `GITHUB_TOKEN` bị bỏ qua → đụng rate limit GitHub     | Thêm `crawler/utils/envfile.py` nạp allowlist (`GITHUB_TOKEN`, `NVD_API_KEY`, `CRAWLER_OFFLINE`); biến môi trường shell vẫn ưu tiên; token không được in ra |
| Tag trùng `v2.0.5` / `2.0.5`               | `map_tags_to_versions` dừng với lỗi                   | Giữ tag ưu tiên (dạng `v`-prefix trước dạng thuần số)                                                                                                       |
| OSV `fixed` là commit SHA (khoảng `GIT`)   | Pydantic báo lỗi PEP 440 khi đưa vào `fixed_versions` | Chỉ giá trị hợp PEP 440 vào `events`/`fixed_versions`; commit SHA chuyển vào `patch_commits`                                                                |


Ngoài ra, lệnh `run` bắt thêm `ValueError` / `OSError` để báo lỗi gọn thay vì đổ traceback
đầy đủ.

---

## 14. Ba case study từ dữ liệu live

### 14.1. `version_api_dataflow` — CVE-2025-66471 (giải nén khi streaming)

```text
Advisory canonical:  GHSA-2xpw-w6gg-jr37 (CVE-2025-66471, PYSEC-2026-1994)
Mức độ / CWE:        HIGH / CWE-409 (khuếch đại dữ liệu nén)
CVSS 4.0:            AV:N/AC:L/AT:P/PR:N/UI:N/VC:N/VI:N/VA:H/SC:N/SI:N/SA:H
Khoảng bị ảnh hưởng: 1.0 → 2.5.0 (đã sửa ở 2.6.0); 98 phiên bản trong danh mục
Module:              urllib3.response
Symbol chủ chốt:     ContentDecoder, DeflateDecoder, _decode, _decompress, _get_decoder
Tiền đề:             gọi API streaming (stream(), read(amt=...), read1(), read_chunked(),
                     readinto()) trên response nén; decoding không bị tắt
Luồng dữ liệu:       untrusted_input → API dễ tổn thương
Điều kiện an toàn:   phiên bản ≥ 2.6.0
Bằng chứng patch:    commit c19571de34c47de3a766541b041637ba5f716ed7
Regression test:     test/test_response.py
Khắc phục:           nâng lên ≥ 2.6.0 (kèm Brotli ≥ 1.2.0 nếu dùng extra brotli)
Dương tính giả:      chỉ import urllib3 mà không stream nội dung nén
Logic phán quyết:    version ∈ khoảng ∧ gọi API streaming ∧ nội dung từ nguồn không tin cậy
```

**Ý nghĩa:** thông tin “đang dùng 2.4.0” tự thân chưa đủ để kết luận rủi ro; ứng dụng chỉ thực
sự bị ảnh hưởng khi đọc theo chunk dữ liệu nén từ nguồn không tin cậy.

### 14.2. `version_api_dataflow` — CVE-2024-37891 (rò `Proxy-Authorization` khi redirect)

```text
Advisory canonical:  GHSA-34jh-p97f-mpxf (CVE-2024-37891, PYSEC-2026-1995)
Mức độ / CWE:        MODERATE / CWE-669 (chuyển tài nguyên sai miền tin cậy)
Đã sửa ở:            1.26.19 (nhánh 1.x) và 2.2.2 (nhánh 2.x)
Tiền đề:             dùng ProxyManager / proxy HTTP(S) ∧ ứng dụng đi theo redirect
Luồng dữ liệu:       redirect_location_header → trình xử lý redirect
Module:              urllib3.util.retry (remove_headers_on_redirect)
Điều kiện an toàn:   ≥ 2.2.2, hoặc ≥ 1.26.19 trên nhánh 1.x
Bằng chứng patch:    commit accff72ecc2f6cf5a76d9570198a93ac7c90270e
Regression test:     test/test_retry.py, test/with_dummyserver/test_poolmanager.py
Kiểm chứng query:    phiên bản 2.4.0 → Affected: no (đúng, vì 2.4.0 > 2.2.2)
```

**Hạn chế lộ ra:** pattern hiện chỉ chọn **một** nhánh `fixed_versions` cho
`upgrade_guidance`, nên có trường hợp khuyến nghị “nâng lên 1.26.19” trong khi
`negative_conditions` lại nêu “≥ 2.2.2”. Người dùng nhánh 2.x nếu làm theo sẽ nhận khuyến nghị
sai hướng. Hướng xử lý: xuất khuyến nghị theo từng nhánh bảo trì (mục 16).

### 14.3. `version_api_dataflow` — CVE-2025-50182 (redirect trên runtime Emscripten)

```text
Advisory canonical:  GHSA-48p4-8xcf-vxj5 (CVE-2025-50182, PYSEC-2026-1997)
Mức độ / CWE:        MODERATE / CWE-601 (redirect tới đích không tin cậy); có dấu hiệu SSRF
Khoảng bị ảnh hưởng: 2.2.0 → 2.4.0 (đã sửa ở 2.5.0) — chỉ 6 phiên bản
Module:              urllib3.contrib.emscripten.fetch
Tiền đề:             chạy trên Pyodide/Emscripten ∧ ứng dụng đi theo redirect
Luồng dữ liệu:       redirect_location_header → trình xử lý redirect
Điều kiện an toàn:   phiên bản ≥ 2.5.0
Bằng chứng patch:    commit 7eb4a2aafe49a279c29b6d1f0ed0f42e9736194f
Regression test:     test/contrib/emscripten/test_emscripten.py
Dương tính giả:      backend Python thuần, không chạy trong môi trường Emscripten
```

**Ý nghĩa:** ứng dụng server-side dùng 2.3.0 gần như chắc chắn *không* bị ảnh hưởng vì lỗi nằm
trong nhánh `contrib.emscripten`. Nếu chỉ so version, toàn bộ người dùng 2.2–2.4 sẽ nhận cảnh
báo sai.

```bash
python -m crawler query --package urllib3 --version 2.4.0 --output data
```

---

## 15. Tính tái lập và kiểm chứng chất lượng


| Cơ chế                          | Tác dụng                                                                                           |
| ------------------------------- | -------------------------------------------------------------------------------------------------- |
| JSONL sắp thứ tự xác định       | Input giống nhau → `record_id` và nội dung giống nhau; diff giữa hai lần crawl là diff ngữ nghĩa   |
| `data/manifest.json`            | Lưu SHA-256 từng file xuất ra; kiểm tra toàn vẹn mà không cần chạy lại pipeline                    |
| `data/raw/` cache theo nội dung | `--skip-crawl` cho phép chạy lại từ bước chuẩn hoá mà không gọi mạng                               |
| Bộ test offline                 | **244 test** trên Python 3.12.3; kiểm tra tính xác định tại `tests/test_deterministic_pipeline.py` |


**Cổng chất lượng đã chạy ở lần cập nhật này:** `pytest` (244 passed) · `ruff check` ·
`ruff format --check` · `mypy crawler` — toàn bộ đạt.

---

## 16. Hạn chế còn tồn tại 

Xếp theo mức ảnh hưởng tới chất lượng phán quyết SAST:


| Ưu tiên | Hạn chế                                                                                                 | Đề xuất                                                                              |
| ------- | ------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------ |
| P0      | Khoảng `GIT` mở làm phình `advisory.affected_versions` (7/19 advisory; `range_resolution_rate` = 0.632) | Không chiếu khoảng `GIT` lên danh mục PyPI, hoặc bỏ qua khi đã có khoảng `ECOSYSTEM` |
| P0      | Nhiễu khi rút symbol từ diff (gán tên hàm test vào module nguồn)                                        | Tách symbol theo file gốc (`src/` vs `test/`); không suy tên module từ file test     |
| P1      | `upgrade_guidance` không theo nhánh bảo trì                                                             | Xuất khuyến nghị riêng cho từng nhánh (1.x / 2.x)                                    |
| P1      | 3 pattern `version_only` thiếu điều kiện sử dụng                                                        | Giữ ở mức SCA cho đến khi có bằng chứng patch                                        |
| P2      | Endpoint list GitHub chỉ lấy trang đầu (nếu chưa mở rộng)                                               | Mở rộng phân trang để nâng `version_coverage`                                        |
| P2      | Rút symbol không phải phân tích liên thủ tục                                                            | Định vị là tín hiệu cho engine SAST, không thay thế data-flow analysis               |
| P2      | Nhánh NVD chưa bật mặc định                                                                             | CWE/CVSS hiện lấy từ OSV; kích hoạt NVD khi cần bổ sung                              |


---

## 17. Hướng mở rộng sang thư viện khác

1. Thêm `configs/<package>.yaml` khai báo định danh package, repository và nguồn được bật.
2. Tái sử dụng nguyên tầng retrieval, model, resolver, exporter và CLI — không cần sửa code
  lõi.
3. Điều chỉnh heuristic đọc changelog/commit nếu repo đích dùng quy ước khác (`urllib3` dùng
  `CHANGES.rst`).
4. Chạy lại validate và thống kê **trước khi** công bố độ phủ; các chỉ số ở mục 12 chỉ đúng
  cho `urllib3`.

---

## 18. Bài học vận hành

1. **Vertical slice trước, mở rộng bề rộng sau.** Đi hết một đường end-to-end giúp phát hiện
  lỗ hợp đồng dữ liệu khi chi phí sửa còn thấp.
2. **Fixture không thay thế dữ liệu thật.** Bộ test offline đạt 100% vẫn không ngăn ba lỗi
  runtime lộ ra trên crawl live (tag trùng, commit SHA trong `fixed`, `.env` không được nạp).
3. **Validate nghiêm chặt mang lại tín hiệu hành động.** 7 lỗi `contradictory_ranges` chỉ đúng
  chỗ cần sửa; nếu tầng validate “dễ tính”, lỗi sẽ âm thầm đi vào kết quả phán quyết.
4. **Tách khoảng SCA khỏi điều kiện sử dụng SAST là insight cốt lõi.** Giá trị của hệ thống
  bắt nguồn từ ranh giới này.
5. **`--offline --fixture-dir` là yêu cầu bắt buộc cho CI**, không chỉ là tiện ích phát triển —
  không có nó thì pipeline phụ thuộc mạng và dễ đỏ vì rate limit thay vì vì lỗi code.

---

## 19. Kết luận và khuyến nghị

### Kết luận

Việc chọn `urllib3` đã cho phép hoàn thành một bản pilot đầy đủ bằng chứng: crawl từ nguồn có
thẩm quyền, giữ provenance đến từng byte, giải đúng phiên bản bị ảnh hưởng, và gắn điều kiện
API / cấu hình / luồng dữ liệu mà SAST cần. Trên dữ liệu thật, hệ thống sinh **19 security
pattern**, trong đó **16/19** có điều kiện sử dụng cụ thể — tức phần lớn phát hiện có thể được
thu hẹp vượt mức so-version thuần.

### Khuyến nghị hành động tiếp theo


| Ưu tiên | Hành động                                                   | Mục tiêu                                                          |
| ------- | ----------------------------------------------------------- | ----------------------------------------------------------------- |
| 1       | Sửa xử lý khoảng OSV loại `GIT` mở                          | Nâng `range_resolution_rate` và loại 7 lỗi `contradictory_ranges` |
| 2       | Làm sạch rút symbol từ diff                                 | Giảm nhiễu symbol test trong security pattern                     |
| 3       | Xuất `upgrade_guidance` theo nhánh bảo trì                  | Tránh khuyến nghị nâng cấp sai nhánh                              |
| 4       | Review thủ công case study live trước khi dùng ngoài nội bộ | Bảo đảm chất lượng trình bày cho stakeholder bên ngoài            |


Nền tảng provenance, tính xác định và cổng validate hiện đã đủ vững để các cải thiện trên được
đo bằng chỉ số, không phụ thuộc đánh giá cảm tính.
