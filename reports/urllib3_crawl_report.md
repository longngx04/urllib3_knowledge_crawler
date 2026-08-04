# Báo cáo thu thập tri thức bảo mật cho `urllib3`

*Phiên bản báo cáo: sau lần crawl live ngày 04/08/2026 (dữ liệu tại `./data`).*

---

## 1. Tóm tắt cho người ra quyết định

Dự án này xây dựng một **cơ sở tri thức bảo mật theo từng phiên bản (version-aware)** cho
thư viện [`urllib3`](https://github.com/urllib3/urllib3), phục vụ hệ thống **SAST có AI hỗ
trợ**. Mục tiêu không chỉ là trả lời "phiên bản đang dùng có nằm trong khoảng bị ảnh hưởng
hay không" — đó là việc của SCA — mà là trả lời câu hỏi khó hơn: *code của ứng dụng có thực
sự chạm tới API, cấu hình và luồng dữ liệu khiến lỗ hổng trở nên khai thác được hay không*,
và khi nào một phát hiện nên bị coi là dương tính giả.

Pipeline giữ nguyên byte gốc từ upstream kèm băm SHA-256 để truy nguyên, chuẩn hoá thành
các bản ghi có kiểu (typed records), hợp nhất alias advisory, chiếu khoảng bị ảnh hưởng lên
danh mục phát hành thật của PyPI, bổ sung bằng chứng patch cùng regression test, sinh
security pattern định hướng SAST và tài liệu phục vụ truy hồi (retrieval), cuối cùng là
validate và xuất thống kê có thể tái lập.

**Kết quả lần crawl live (đã kiểm chứng, ghi vào `./data`):**

| Hạng mục | Số lượng |
|---|---|
| Phiên bản `urllib3` trong danh mục | **108** (4 prerelease, 4 bị yank) |
| Advisory sau khi hợp nhất alias | **19** |
| Alias được liên kết (CVE / GHSA / PYSEC) | **57** |
| Bản ghi patch có bằng chứng diff | **21** |
| Security pattern cho SAST | **19** |
| Tài liệu KB phục vụ truy hồi | **92** |
| Độ phủ provenance | **1.00** |
| Tỷ lệ hợp lệ theo schema | **1.00** |

Câu lệnh đã dùng:

```bash
python -m crawler run --config configs/urllib3.yaml --output data
```

Kết luận ngắn: pipeline chạy được end-to-end trên dữ liệu thật, mọi claim bảo mật đều có
provenance, và tri thức xuất ra đủ chi tiết để một engine SAST ra phán quyết dựa trên
*version ∧ API ∧ cấu hình ∧ luồng dữ liệu* thay vì chỉ so version. Tuy nhiên lần crawl
live cũng phơi ra ba lỗi thực thi (đã sửa) và ba vấn đề chất lượng dữ liệu còn tồn (mô tả
chi tiết ở Mục 12 và 13) — trong đó đáng chú ý nhất là việc khoảng `GIT` mở làm phình tập
phiên bản bị ảnh hưởng ở tầng advisory.

---

## 2. Vấn đề cần giải quyết

Một feed SCA thông thường cho ta: mã định danh, mô tả, khoảng bị ảnh hưởng, phiên bản đã
sửa và mức độ nghiêm trọng. Cần, nhưng chưa đủ cho SAST:

- **Chỉ so version thì báo động quá nhiều.** Một dịch vụ ghim `urllib3==2.0.5` nhưng không
  bao giờ đi theo redirect hay dùng proxy vẫn bị đánh dấu là "có lỗ hổng".
- **Bỏ mất tiền đề thì lại báo động quá ít.** Nhiều lỗi chỉ phát tác khi ứng dụng bật một
  cấu hình rủi ro, hoặc khi dữ liệu không tin cậy chảy đến đúng sink.
- **Thiếu bằng chứng patch và test thì khuyến nghị khắc phục không kiểm chứng được.** Người
  review không có cách nào xác nhận "nâng lên 2.6.0" thực sự sửa đúng hành vi nào.
- **Thiếu provenance thì AI không phân biệt được sự thật có nguồn với suy đoán.** Đây là
  ranh giới sống còn khi output được dùng để ra quyết định bảo mật.

---

## 3. Vì sao chọn `urllib3`

1. **Độ phổ biến.** `urllib3` là nền của `requests` và phần lớn hệ sinh thái HTTP Python,
   nên tri thức thu được có giá trị thực tế ngay.
2. **Bằng chứng công khai đầy đủ.** PyPI JSON, GitHub tags/releases/changelog/commits, và
   advisory OSV/GHSA đều truy cập được mà không cần feed thương mại.
3. **Đa dạng lớp phát hiện.** Các lỗ hổng của `urllib3` trải đủ ba lớp mà SAST cần: lạm dụng
   API, cấu hình TLS/proxy, và tiền đề luồng dữ liệu qua redirect. Thực tế lần crawl này cho
   ra cả bốn loại `detection_type` (xem Mục 11).
4. **Đo lường được, không mơ hồ.** Một package PEP 440 trưởng thành giúp các chỉ số độ phủ
   trung thực, không bị pha loãng bởi nhiều hệ sinh thái version khác nhau.
5. **Kiến trúc tái sử dụng được.** Toàn bộ định danh package nằm trong
   `configs/urllib3.yaml`; không có sự thật nào về `urllib3` bị hardcode trong logic chung.

---

## 4. Phạm vi và những gì cố ý không làm

**Trong phạm vi (Phase 0–13):** bootstrap CLI, hợp đồng dữ liệu, tầng HTTP an toàn có cache,
danh mục phiên bản PyPI, dữ liệu GitHub release/tag/changelog, advisory OSV + hợp nhất
alias, giải khoảng bị ảnh hưởng, bổ sung patch và regression test, sinh security pattern,
xuất tài liệu KB, validate + thống kê, pipeline CLI đầy đủ kèm `query`, tính tái lập, và
báo cáo này.

**Ngoài phạm vi:** engine SAST hoàn chỉnh; vector database; crawl toàn bộ issue/PR; coi blog
hay bản nháp LLM là nguồn có thẩm quyền cho khoảng bị ảnh hưởng; hỗ trợ production đa
package; sinh mã khai thác; và bắt buộc dùng NVD (nhánh NVD vẫn là tuỳ chọn).

---

## 5. Tri thức mà SAST cần, và nơi lưu trữ tương ứng

| Câu hỏi của engine SAST | Bản ghi / artifact trả lời |
|---|---|
| Thư viện có những phiên bản nào? | `data/normalized/versions.jsonl` |
| Có advisory nào, và các alias của nó? | `data/normalized/advisories.jsonl` + alias resolver |
| Chính xác những phiên bản nào bị ảnh hưởng? | range resolver (`affected_ranges[].resolved`) |
| Symbol, cấu hình, luồng dữ liệu nào liên quan? | `data/normalized/security_patterns.jsonl` |
| Khi nào code là an toàn? | `negative_conditions` trong security pattern |
| Patch và test nào chứng minh bản sửa? | `data/normalized/patches.jsonl` |
| Đoạn văn bản nào để truy hồi cho LLM? | `data/kb/documents.jsonl` |
| Có tin được không? | `provenance` trên mọi bản ghi + `data/stats.json` |

---

## 6. Đánh giá nguồn dữ liệu

| Nguồn | Hạng | Vai trò trong pipeline |
|---|---|---|
| GHSA / ghi chú bảo mật của maintainer | 1 | Mô tả hành vi kỹ thuật, tiền đề, khuyến nghị |
| Tag / commit / test / changelog trên repo chính thức | 1 | Bằng chứng patch, symbol thay đổi, regression test |
| PyPI project JSON | 1 | Danh mục phát hành, ngày, trạng thái yank |
| OSV | 1 | Alias, khoảng bị ảnh hưởng, mức độ nghiêm trọng |
| NVD | tuỳ chọn | Bổ sung CWE/CVSS (chưa nằm trong đường đi mặc định) |

Nguyên tắc xử lý xung đột: **hạng thấp không bao giờ âm thầm ghi đè hạng cao**. Khi hai
nguồn nói khác nhau, cả hai claim đều được giữ kèm lý do, thay vì chọn một và xoá dấu vết.

---

## 7. Kiến trúc: pipeline crawl hoạt động ra sao

```text
configs/urllib3.yaml
  → RetrievalClient + RawStore        (HTTP có timeout/retry/giới hạn kích thước, cache theo SHA-256)
  → adapter PyPI / GitHub / OSV
  → normalizer + alias resolver + range resolver
  → patch enrichment + sinh security pattern + xuất tài liệu KB
  → validate → stats.json / manifest.json
```

Trình tự vận hành thực tế:

1. Nạp `configs/urllib3.yaml` (file cấu hình **không** chứa secret; token đọc từ `.env`
   hoặc biến môi trường).
2. Gọi các nguồn được bật; lưu body gốc cùng metadata trong allowlist vào `data/raw/`. Lần
   crawl live tạo 27 response gốc (~1.7 MB), địa chỉ hoá theo SHA-256 nên lần chạy sau dùng
   lại được bằng `--skip-crawl`.
3. Chuẩn hoá thành các model Pydantic của Phase 1, mỗi bản ghi mang provenance
   (`source_type`, `source_id`, `raw_sha256`, `retrieved_at`, `extractor_version`).
4. Hợp nhất alias theo thứ tự ưu tiên GHSA > CVE > OSV/PYSEC, rồi chiếu khoảng bị ảnh hưởng
   lên đúng danh mục phiên bản PyPI.
5. Lấy commit từ các URL fix trong advisory; phân tích diff để rút file, symbol, guard mới
   thêm và regression test.
6. Sinh security pattern và tài liệu KB từ bằng chứng đã có.
7. Validate rồi xuất `stats.json`, `manifest.json`, `validation_errors.json`.

Chế độ offline phục vụ payload fixture qua `httpx.MockTransport` nhưng vẫn chạy thật logic
dựng URL và đường đi cache — nhờ vậy toàn bộ pipeline kiểm chứng được mà không phụ thuộc
mạng.

---

## 8. Thiết kế schema

Sáu họ bản ghi: `version`, `advisory`, `patch`, `security_pattern`, `kb_document`, và
`provenance` dùng chung. Schema JSON Draft 2020-12 nằm trong `schemas/`, luôn đồng bộ với
model Pydantic. Quy ước: giá trị chưa biết là `null` (không bịa mặc định); so sánh phiên bản
luôn qua `packaging.version.Version`, không so chuỗi.

---

## 9. Giải phiên bản và alias

- Mọi release PyPI phân tích được đều được chuẩn hoá theo PEP 440; khoá không phân tích được
  sẽ bị báo cáo chứ không âm thầm bỏ.
- Chỉ liên kết alias khi có liên kết tường minh từ nguồn; cụm alias mơ hồ được báo cáo.
- Khoảng bị ảnh hưởng dựng từ `events` của OSV và specifier PEP 440; sentinel `0` nghĩa là
  "từ đầu"; **không bao giờ tự suy ra phiên bản đã sửa** khi nguồn không nói.

Kết quả live: `alias_resolution_rate = 1.00` (57 alias, không có cụm mơ hồ),
`version_coverage = 0.907` — tức 98/108 phiên bản khớp được với tag Git hoặc commit, phần
còn lại là các release rất cũ (0.2–1.x đầu) không có tag tương ứng trên GitHub.

---

## 10. Bằng chứng patch và regression test

21 bản ghi patch được dựng từ commit chính thức, mỗi bản ghi giữ `commit_sha`, `parent_sha`,
danh sách file thay đổi, symbol thay đổi, guard mới thêm và regression test liên quan.
`patch_resolution_rate = 1.00` và `fixed_release_verification_rate = 1.00`: mọi phiên bản
được nêu là "đã sửa" đều tồn tại thật trong danh mục PyPI.

Ví dụ bản ghi patch cho CVE-2023-43804 (`GHSA-v845-jxx5-vc9f`), commit
`01220354d389cd05474713f8c982d05c9b17aafb`:

```text
changed_files: src/urllib3/util/retry.py, test/test_retry.py,
               test/with_dummyserver/test_poolmanager.py, CHANGES.rst
added_guards:  assert retry.remove_headers_on_redirect == {"authorization", "cookie"}
               assert "Cookie" not in data
fixed_versions: 1.26.17, 2.0.6
confidence:     0.95 — "official repository commit with extracted diff evidence"
```

Guard trích từ diff chính là thứ giúp phân biệt "đã nâng version" với "đã thực sự đóng lỗ
hổng": nó cho biết hành vi nào mới được kiểm tra sau bản sửa.

---

## 11. Sinh security pattern

Thứ tự ưu tiên bằng chứng: khoảng có cấu trúc → văn bản advisory → diff của patch →
regression test → changelog. Suy luận không có bằng chứng chống lưng bị ghi rõ trong
`confidence.rationale` (ví dụ `"unsupported inference: changelog text not supplied"`), và
bản nháp do LLM sinh — nếu sau này thêm — không được phép thay đổi khoảng bị ảnh hưởng có
thẩm quyền.

Phân bố 19 pattern của lần crawl live theo lớp phát hiện:

| `detection_type` | Số pattern | Ý nghĩa cho SAST |
|---|---|---|
| `version_api_dataflow` | 10 | Cần version ∧ gọi API ∧ có luồng dữ liệu không tin cậy |
| `version_api` | 4 | Cần version ∧ có gọi API liên quan |
| `version_api_configuration_dataflow` | 2 | Cần thêm cả cấu hình rủi ro |
| `version_only` | 3 | Chưa rút được điều kiện sử dụng — chỉ nên coi là mức SCA |

Theo mức độ: 1 CRITICAL, 9 HIGH, 9 MODERATE. Điểm hữu dụng trung bình cho SAST
(`average_sast_usefulness_score`) là **0.816**; ba pattern `version_only` là nguyên nhân
chính kéo điểm xuống, vì advisory tương ứng không kèm commit fix nên không rút được symbol.

---

## 12. Phương pháp validate và các phát hiện thật

Bước validate kiểm tra schema, sự hiện diện provenance, advisory canonical trùng lặp và các
tín hiệu bất nhất. Mọi lỗi đều kèm `record_id` và lý do; chế độ strict trả exit code 1.

Kết quả live (`data/stats.json`, `data/validation_errors.json`):

| Chỉ số | Giá trị | Nhận xét |
|---|---|---|
| `provenance_coverage` | 1.000 | Mọi bản ghi đều truy nguyên được về byte gốc |
| `schema_validation_rate` | 1.000 | Không bản ghi nào lệch schema |
| `duplicate_rate` | 0.000 | Không có advisory canonical trùng |
| `alias_resolution_rate` | 1.000 | 57 alias, không cụm mơ hồ |
| `patch_resolution_rate` | 1.000 | 21/21 patch có bằng chứng diff |
| `fixed_release_verification_rate` | 1.000 | Phiên bản "đã sửa" đều tồn tại trên PyPI |
| `version_coverage` | 0.907 | 98/108 phiên bản khớp tag/commit |
| `range_resolution_rate` | **0.632** | 7/19 advisory có khoảng bất nhất — xem dưới |
| `average_sast_usefulness_score` | 0.816 | Bị kéo xuống bởi 3 pattern `version_only` |

Validate đã bắt đúng **7 lỗi `contradictory_ranges`**, tất cả cùng một dạng: phiên bản được
advisory nêu là "đã sửa" lại xuất hiện trong tập phiên bản bị ảnh hưởng đã giải. Ví dụ với
CVE-2023-45803 (`GHSA-g4mx-q9vg-27p4`), `1.26.18` và `2.0.7` vừa là fixed version vừa nằm
trong `affected_versions`.

Nguyên nhân đã truy được: advisory OSV có kèm khoảng loại `GIT` chỉ chứa duy nhất sự kiện
`introduced: "0"` mà không có `fixed`. Khi resolver chiếu khoảng đó lên danh mục PyPI, nó
khớp **toàn bộ 108 phiên bản**; hợp (union) ở tầng advisory kéo theo cả những phiên bản đã
sửa. Điều quan trọng: **các khoảng `ECOSYSTEM` bên trong vẫn đúng** —
`affected_ranges[].resolved` cho CVE-2023-45803 nêu chính xác `2.0.0`–`2.0.6` và
`0.2`–`1.26.17`. Nghĩa là sai lệch nằm ở trường tổng hợp `advisory.affected_versions`, và
`security_pattern.version.resolved` (thứ mà `query` thực sự dùng) vẫn cho kết quả đúng: khi
truy vấn `2.4.0`, CVE-2024-37891 được trả về `Affected: no` như mong đợi.

Việc validate phát hiện được lỗi này, thay vì im lặng cho qua, đúng là mục đích thiết kế của
tầng validate.

---

## 13. Sự cố trong lần crawl live và cách xử lý

Ba lỗi chỉ xuất hiện khi gặp dữ liệu thật, đều đã sửa kèm test hồi quy:

1. **Không nạp `.env`.** CLI chỉ đọc `os.getenv`, nên `GITHUB_TOKEN` trong `.env` bị bỏ qua
   và lần crawl đầu tiên đụng rate limit của GitHub. Đã bổ sung
   `crawler/utils/envfile.py`, nạp các khoá trong allowlist (`GITHUB_TOKEN`, `NVD_API_KEY`,
   `CRAWLER_OFFLINE`) khi import CLI; biến môi trường của shell vẫn được ưu tiên, và giá trị
   token không bao giờ được in ra.
2. **Tag trùng khi map version.** Repo thật có cả `v2.0.5` và `2.0.5` trỏ về cùng release,
   khiến `map_tags_to_versions` báo lỗi. Đã sửa để giữ tag ưu tiên (`v`-prefix trước dạng
   thuần số) thay vì bỏ cuộc.
3. **`fixed` của OSV là commit SHA.** Với khoảng loại `GIT`, giá trị `fixed` là hash commit
   chứ không phải phiên bản; đưa nó vào `fixed_versions` làm Pydantic báo lỗi PEP 440. Đã
   sửa: chỉ giá trị hợp PEP 440 mới vào `events`/`fixed_versions`, còn commit SHA đi vào
   `patch_commits`.

Ngoài ra CLI `run` nay bắt thêm `ValueError`/`OSError` để báo lỗi gọn gàng thay vì đổ
traceback. Toàn bộ nhóm sửa này nằm trong
[PR #13](https://github.com/longngx04/urllib3_knowledge_crawler/pull/13).

---

## 14. Ba tình huống thực tế (case study từ dữ liệu live)

### A. `version_api_dataflow` — CVE-2025-66471, giải nén khi streaming

```text
Advisory canonical:  GHSA-2xpw-w6gg-jr37 (CVE-2025-66471, PYSEC-2026-1994)
Mức độ / CWE:        HIGH / CWE-409 (khuếch đại dữ liệu nén)
CVSS 4.0:            AV:N/AC:L/AT:P/PR:N/UI:N/VC:N/VI:N/VA:H/SC:N/SI:N/SA:H
Khoảng bị ảnh hưởng: 1.0 → 2.5.0 (đã sửa ở 2.6.0), 98 phiên bản trong danh mục
Module liên quan:    urllib3.response
Symbol chủ chốt:     ContentDecoder, DeflateDecoder, _decode, _decompress, _get_decoder
Tiền đề bắt buộc:    gọi API streaming (stream(), read(amt=...), read1(), read_chunked(),
                     readinto()) trên response nén, không tắt decoding
Luồng dữ liệu:       untrusted_input → API dễ tổn thương
Điều kiện an toàn:   phiên bản đã ở 2.6.0 trở lên
Bằng chứng patch:    commit c19571de34c47de3a766541b041637ba5f716ed7
Regression test:     test/test_response.py
Khắc phục:           nâng lên ≥ 2.6.0 (kèm Brotli ≥ 1.2.0 nếu dùng extra brotli)
Dương tính giả:      code chỉ import urllib3 mà không stream nội dung nén
Logic phán quyết:    version ∈ khoảng ∧ có gọi API streaming ∧ nội dung đến từ nguồn không tin cậy
```

Đây là ví dụ rõ nhất cho luận điểm của dự án: chỉ riêng "đang dùng 2.4.0" chưa nói được gì;
ứng dụng chỉ thực sự rủi ro khi có đọc theo chunk dữ liệu nén từ nguồn không tin cậy.

### B. `version_api_dataflow` với tiền đề cấu hình — CVE-2024-37891, rò `Proxy-Authorization` khi redirect

```text
Advisory canonical:  GHSA-34jh-p97f-mpxf (CVE-2024-37891, PYSEC-2026-1995)
Mức độ / CWE:        MODERATE / CWE-669 (chuyển tài nguyên sai miền tin cậy)
Đã sửa ở:            1.26.19 (nhánh 1.x) và 2.2.2 (nhánh 2.x)
Tiền đề bắt buộc:    đang dùng ProxyManager hoặc proxy HTTP(S)
                     ∧ ứng dụng đi theo redirect
Luồng dữ liệu:       redirect_location_header → trình xử lý redirect
Module liên quan:    urllib3.util.retry (remove_headers_on_redirect)
Điều kiện an toàn:   phiên bản ≥ 2.2.2 (hoặc ≥ 1.26.19 trên nhánh 1.x)
Bằng chứng patch:    commit accff72ecc2f6cf5a76d9570198a93ac7c90270e
Regression test:     test/test_retry.py, test/with_dummyserver/test_poolmanager.py
Kiểm chứng query:    truy vấn 2.4.0 → "Affected: no" (đúng, vì 2.4.0 > 2.2.2)
```

Tình huống này bộc lộ một hạn chế thật của bản hiện tại: pattern chỉ chọn **một** nhánh
`fixed_versions` để đưa vào khuyến nghị, nên `upgrade_guidance` ghi "nâng lên 1.26.19 hoặc
mới hơn" trong khi `negative_conditions` lại nói "≥ 2.2.2". Với người dùng nhánh 2.x, lời
khuyên 1.26.19 là sai hướng. Cách xử lý đúng là giữ khuyến nghị theo từng nhánh bảo trì
(xem Mục 16).

### C. `version_api_dataflow` — CVE-2025-50182, redirect bị bỏ qua trên runtime Emscripten

```text
Advisory canonical:  GHSA-48p4-8xcf-vxj5 (CVE-2025-50182, PYSEC-2026-1997)
Mức độ / CWE:        MODERATE / CWE-601 (redirect tới địa chỉ không tin cậy), có dấu hiệu SSRF
Khoảng bị ảnh hưởng: 2.2.0 → 2.4.0 (đã sửa ở 2.5.0) — chỉ 6 phiên bản, khoảng rất gọn
Module liên quan:    urllib3.contrib.emscripten.fetch
Tiền đề bắt buộc:    chạy trên Pyodide/Emscripten ∧ ứng dụng đi theo redirect
Luồng dữ liệu:       redirect_location_header → trình xử lý redirect
Điều kiện an toàn:   phiên bản ≥ 2.5.0
Bằng chứng patch:    commit 7eb4a2aafe49a279c29b6d1f0ed0f42e9736194f
Regression test:     test/contrib/emscripten/test_emscripten.py
Dương tính giả:      backend Python thuần, không chạy trong môi trường Emscripten
```

Case này minh hoạ giá trị của điều kiện API: một ứng dụng server-side dùng 2.3.0 gần như
chắc chắn *không* bị ảnh hưởng, vì lỗi nằm trong nhánh `contrib.emscripten`.

Câu lệnh truy vấn dùng cho các case trên:

```bash
python -m crawler query --package urllib3 --version 2.4.0 --output data
```

---

## 15. Tính tái lập

- Output JSONL có thứ tự xác định; input giống nhau cho ra `record_id` và nội dung giống
  nhau, nên diff giữa hai lần crawl là diff *ngữ nghĩa*, không phải nhiễu thứ tự.
- `data/manifest.json` lưu SHA-256 của từng file xuất ra, cho phép kiểm tra toàn vẹn artifact
  mà không cần chạy lại pipeline.
- `data/raw/` là cache địa chỉ hoá theo nội dung; `--skip-crawl` cho phép chạy lại các bước
  chuẩn hoá trở về sau mà không gọi mạng.
- Bộ test mặc định (**244 test**, Python 3.12.3) chạy hoàn toàn offline; kiểm tra tính xác
  định nằm ở `tests/test_deterministic_pipeline.py`.
- Cổng chất lượng đã chạy ở lần cập nhật này: `pytest` (244 passed), `ruff check`,
  `ruff format --check`, `mypy crawler` — tất cả xanh.

---

## 16. Hạn chế đã biết và việc nên làm tiếp

Xếp theo mức ảnh hưởng tới chất lượng phán quyết SAST:

1. **Khoảng `GIT` mở làm phình `advisory.affected_versions`** (7/19 advisory,
   `range_resolution_rate` 0.632). Cách sửa đề xuất: không chiếu khoảng loại `GIT` lên danh
   mục PyPI, hoặc bỏ qua khoảng `GIT` khi advisory đã có khoảng `ECOSYSTEM`. Đây là việc nên
   làm trước tiên.
2. **Nhiễu khi rút symbol từ diff.** Việc rút symbol dựa trên regex và gán tên hàm test cho
   module nguồn, nên xuất hiện các symbol vô nghĩa như
   `urllib3.util.retry.test_retry_set_remove_headers_on_redirect` hay
   `urllib3.response.git_clone`. Cách sửa: tách symbol theo file gốc (`src/` so với `test/`)
   và không suy ra tên module từ file test.
3. **Khuyến nghị nâng cấp không theo nhánh bảo trì.** Như case B, advisory sửa trên cả 1.x và
   2.x nhưng `upgrade_guidance` chỉ nêu một nhánh. Nên xuất khuyến nghị theo từng nhánh.
4. **Ba pattern `version_only`.** Advisory không kèm commit fix nên không rút được điều kiện
   sử dụng; các pattern này chỉ nên dùng ở mức SCA cho tới khi có bằng chứng patch.
5. **Endpoint dạng list của GitHub chỉ lấy trang đầu** nếu không mở rộng, nên
   `version_coverage` (0.907) chưa phải trần thật.
6. **Rút symbol không phải phân tích liên thủ tục.** Nó cho biết *nên tìm gì*, không thay thế
   được data-flow analysis của engine SAST.
7. **Nhánh NVD vẫn tuỳ chọn** và chưa nằm trong đường đi mặc định; CWE/CVSS hiện lấy từ OSV.

---

## 17. Mở rộng sang thư viện khác

1. Thêm `configs/<package>.yaml` khai báo định danh package, repo và nguồn được bật.
2. Tái sử dụng nguyên tầng retrieval, model, resolver, exporter và CLI — không cần sửa code
   lõi.
3. Điều chỉnh heuristic đọc changelog/commit nếu quy ước repo khác (`urllib3` dùng
   `CHANGES.rst`).
4. Chạy lại validate và thống kê **trước khi** tuyên bố độ phủ; các chỉ số ở Mục 12 là dành
   riêng cho `urllib3`.

---

## 18. Bài học rút ra

- **Vertical slice phơi lỗ hợp đồng dữ liệu sớm.** Đi hết một đường end-to-end trước khi mở
  rộng bề rộng connector giúp phát hiện vấn đề schema khi giá thành sửa còn thấp.
- **Fixture không thay thế được dữ liệu thật.** Bộ test offline xanh 100% mà lần crawl live
  vẫn lộ ba lỗi (tag trùng, commit SHA trong `fixed`, `.env` không nạp). Fixture chứng minh
  logic; dữ liệu thật chứng minh giả định.
- **Validate ồn ào tốt hơn validate im lặng.** 7 lỗi `contradictory_ranges` là tin xấu về
  dữ liệu nhưng là tin tốt về hệ thống: chúng chỉ đúng chỗ cần sửa thay vì âm thầm hạ chất
  lượng phán quyết.
- **Tách khoảng SCA khỏi điều kiện sử dụng SAST là insight cốt lõi** của sản phẩm; mọi giá
  trị còn lại đều bắt nguồn từ ranh giới này.
- **`--offline --fixture-dir` là bắt buộc** để chứng minh toàn pipeline mà không lệ thuộc
  mạng, nhất là trong CI.

---

## 19. Kết luận

Chọn `urllib3` cho phép thực hiện một bản pilot trọn vẹn và có bằng chứng: crawl từ nguồn
có thẩm quyền, giữ provenance đến từng byte, giải chính xác các phiên bản bị ảnh hưởng, và
gắn kèm điều kiện API / cấu hình / luồng dữ liệu mà SAST cần. Trên dữ liệu thật, hệ thống
sinh ra 19 security pattern với 16/19 pattern có điều kiện sử dụng cụ thể — tức phần lớn
phát hiện có thể được thu hẹp vượt mức so-version thuần.

Đồng thời báo cáo này không làm nhẹ những gì còn dở: khoảng `GIT` mở khiến 7 advisory có
tập phiên bản bị ảnh hưởng phình ra ở tầng tổng hợp, và việc rút symbol còn lẫn tên hàm
test. Cả hai đều đã khoanh vùng được nguyên nhân và có hướng sửa cụ thể ở Mục 16. Nền tảng
truy nguyên, tính xác định và cổng validate đã đủ chắc để những cải thiện đó được đo lường
thay vì phỏng đoán.
