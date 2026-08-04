# Báo cáo: crawl tri thức bảo mật của `urllib3`

*Bản cập nhật sau lần crawl live ngày 04/08/2026. Số liệu trong báo cáo lấy từ `./data`.*

---

## 1. Tóm tắt

Chúng tôi làm một cơ sở tri thức bảo mật cho [`urllib3`](https://github.com/urllib3/urllib3),
gắn với từng phiên bản cụ thể, để phục vụ SAST có AI hỗ trợ.

SCA đã trả lời được câu "phiên bản này có nằm trong danh sách bị ảnh hưởng không". Câu hỏi
mà SAST cần trả lời khó hơn nhiều: *code của ứng dụng có thật sự chạm vào API, cấu hình và
luồng dữ liệu khiến lỗ hổng đó khai thác được hay không?* Và ngược lại, khi nào thì một cảnh
báo nên bị loại vì chắc chắn là dương tính giả? Đó là khoảng trống mà dự án này nhắm vào.

Cách làm: giữ nguyên byte gốc tải về kèm băm SHA-256 để lúc nào cũng lần được về nguồn,
chuẩn hoá thành bản ghi có kiểu rõ ràng, gom các alias của cùng một advisory về một mối,
chiếu khoảng bị ảnh hưởng lên danh sách release thật trên PyPI, rồi bồi thêm bằng chứng từ
commit vá và regression test. Từ đống bằng chứng đó mới sinh ra security pattern cho SAST và
tài liệu để LLM truy hồi. Cuối cùng là validate và xuất thống kê có thể chạy lại y hệt.

Lần crawl live vừa rồi ra kết quả như sau:

| Hạng mục | Số lượng |
|---|---|
| Phiên bản `urllib3` thu được | **108** (4 prerelease, 4 bị yank) |
| Advisory sau khi gom alias | **19** |
| Alias liên kết được (CVE / GHSA / PYSEC) | **57** |
| Bản ghi patch có bằng chứng diff | **21** |
| Security pattern cho SAST | **19** |
| Tài liệu KB để truy hồi | **92** |
| Độ phủ provenance | **1.00** |
| Tỷ lệ hợp schema | **1.00** |

Chỉ một câu lệnh:

```bash
python -m crawler run --config configs/urllib3.yaml --output data
```

Nói ngắn gọn: pipeline chạy trọn vẹn trên dữ liệu thật, mọi kết luận bảo mật đều có nguồn
kèm theo, và dữ liệu xuất ra đủ để một engine SAST phán quyết theo *version ∧ API ∧ cấu hình
∧ luồng dữ liệu* chứ không chỉ so số phiên bản. Nhưng chạy thật cũng lộ ra ba lỗi (đã sửa)
và ba điểm yếu dữ liệu vẫn còn đó — nặng nhất là chuyện khoảng `GIT` mở làm phình tập phiên
bản bị ảnh hưởng. Chi tiết ở mục 12 và 13.

---

## 2. Vì sao chỉ so version là không đủ

Feed SCA cho ta mã định danh, mô tả, khoảng bị ảnh hưởng, phiên bản đã vá, mức nghiêm trọng.
Cần, nhưng đem vào SAST thì hụt ở bốn chỗ:

- **Báo động thừa.** Một service ghim `urllib3==2.0.5` nhưng không bao giờ đi theo redirect,
  không dùng proxy, vẫn bị gắn cờ "có lỗ hổng". Lập trình viên nhìn vài lần rồi thôi không
  nhìn nữa.
- **Bỏ sót.** Nhiều lỗi chỉ phát tác khi ứng dụng bật đúng một cấu hình rủi ro, hoặc khi dữ
  liệu không tin cậy chảy tới đúng sink. Không mô tả được tiền đề thì không phát hiện được.
- **Khuyến nghị không kiểm chứng được.** Bảo "nâng lên 2.6.0" thì người review chẳng có cách
  nào biết bản đó thật sự đổi hành vi gì.
- **AI không phân biệt được đâu là sự thật, đâu là suy đoán.** Thiếu provenance thì mọi output
  đều đáng ngờ như nhau — mà đây lại là dữ liệu dùng để ra quyết định bảo mật.

---

## 3. Vì sao chọn `urllib3`

`urllib3` nằm dưới `requests` và gần như toàn bộ hệ sinh thái HTTP của Python, nên tri thức
thu được dùng được ngay, không phải bài tập cho vui.

Bằng chứng của nó cũng công khai và đầy đủ: PyPI JSON, tag/release/changelog/commit trên
GitHub, advisory OSV và GHSA — không cần mua feed thương mại nào.

Quan trọng hơn, lỗ hổng của `urllib3` trải đủ các lớp mà SAST quan tâm: lạm dụng API, cấu
hình TLS/proxy sai, và tiền đề luồng dữ liệu qua redirect. Lần crawl này ra đủ cả bốn loại
`detection_type` (mục 11), tức là bộ dữ liệu không bị lệch về một dạng duy nhất.

Thêm nữa, đây là một package PEP 440 duy nhất và trưởng thành, nên các chỉ số độ phủ đo được
là thật, không bị pha loãng bởi nhiều lược đồ version khác nhau. Và toàn bộ thông tin riêng
của `urllib3` nằm trong `configs/urllib3.yaml` — không có sự thật nào về `urllib3` bị nhét
cứng vào code lõi, nên đổi sang thư viện khác chỉ là đổi file cấu hình.

---

## 4. Làm gì, và cố ý không làm gì

Đã làm (Phase 0–13): dựng CLI, định nghĩa hợp đồng dữ liệu, tầng HTTP an toàn có cache, thu
danh sách phiên bản từ PyPI, đọc release/tag/changelog từ GitHub, lấy advisory từ OSV và gom
alias, giải khoảng bị ảnh hưởng, bồi bằng chứng patch và regression test, sinh security
pattern, xuất tài liệu KB, validate và thống kê, ghép thành pipeline CLI đầy đủ kèm lệnh
`query`, bảo đảm tính tái lập, và viết báo cáo này.

Cố ý không làm: engine SAST hoàn chỉnh, vector database, crawl toàn bộ issue và PR, coi blog
hay bản nháp LLM là nguồn có thẩm quyền cho khoảng bị ảnh hưởng, hỗ trợ production nhiều
package, sinh mã khai thác. Nhánh NVD để ngỏ như tuỳ chọn, không nằm trong đường chạy mặc
định.

---

## 5. SAST cần gì, dữ liệu nào trả lời

| Engine SAST hỏi | Đọc ở đâu |
|---|---|
| Thư viện có những phiên bản nào? | `data/normalized/versions.jsonl` |
| Có advisory nào, alias của nó là gì? | `data/normalized/advisories.jsonl` + alias resolver |
| Chính xác phiên bản nào bị ảnh hưởng? | `affected_ranges[].resolved` do range resolver dựng |
| Symbol, cấu hình, luồng dữ liệu nào liên quan? | `data/normalized/security_patterns.jsonl` |
| Khi nào thì code an toàn? | `negative_conditions` trong security pattern |
| Bản vá và test nào chứng minh? | `data/normalized/patches.jsonl` |
| Đoạn nào để đưa vào truy hồi cho LLM? | `data/kb/documents.jsonl` |
| Tin được đến mức nào? | `provenance` trên từng bản ghi + `data/stats.json` |

---

## 6. Nguồn dữ liệu và thứ tự tin cậy

| Nguồn | Hạng | Dùng để làm gì |
|---|---|---|
| GHSA, ghi chú bảo mật của maintainer | 1 | Hành vi kỹ thuật, tiền đề, cách khắc phục |
| Tag, commit, test, changelog trên repo chính thức | 1 | Bằng chứng vá, symbol thay đổi, regression test |
| PyPI project JSON | 1 | Danh sách release, ngày phát hành, trạng thái yank |
| OSV | 1 | Alias, khoảng bị ảnh hưởng, mức nghiêm trọng |
| NVD | tuỳ chọn | Bổ sung CWE/CVSS, chưa bật mặc định |

Khi hai nguồn nói khác nhau, chúng tôi giữ cả hai kèm lý do thay vì chọn một rồi xoá dấu
vết. Nguồn hạng thấp không bao giờ được âm thầm ghi đè nguồn hạng cao.

---

## 7. Pipeline chạy thế nào

```text
configs/urllib3.yaml
  → RetrievalClient + RawStore     (timeout, retry, giới hạn kích thước, cache theo SHA-256)
  → adapter PyPI / GitHub / OSV
  → normalizer + alias resolver + range resolver
  → bồi patch + sinh security pattern + xuất tài liệu KB
  → validate → stats.json / manifest.json
```

Cụ thể từng bước:

1. Đọc `configs/urllib3.yaml`. File này không chứa secret; token lấy từ `.env` hoặc biến môi
   trường.
2. Gọi các nguồn được bật, lưu body gốc cùng metadata trong allowlist vào `data/raw/`. Lần
   crawl live sinh 27 response gốc, khoảng 1,7 MB. Vì cache đánh địa chỉ theo SHA-256 nên
   lần chạy sau dùng lại được bằng `--skip-crawl`, không cần gọi mạng nữa.
3. Chuẩn hoá thành model Pydantic của Phase 1. Mỗi bản ghi mang theo provenance:
   `source_type`, `source_id`, `raw_sha256`, `retrieved_at`, `extractor_version`.
4. Gom alias theo thứ tự GHSA > CVE > OSV/PYSEC, rồi chiếu khoảng bị ảnh hưởng lên đúng danh
   sách phiên bản PyPI vừa thu được.
5. Tải commit từ các URL vá trong advisory, đọc diff để rút ra file, symbol, guard mới thêm
   và regression test.
6. Sinh security pattern và tài liệu KB từ những bằng chứng đã có.
7. Validate, rồi xuất `stats.json`, `manifest.json` và `validation_errors.json`.

Chế độ offline trả payload fixture qua `httpx.MockTransport`, nhưng vẫn chạy thật phần dựng
URL và đường đi cache. Nhờ vậy kiểm chứng được cả pipeline mà không phụ thuộc mạng — thứ này
quan trọng với CI.

---

## 8. Schema

Sáu họ bản ghi: `version`, `advisory`, `patch`, `security_pattern`, `kb_document`, và
`provenance` dùng chung cho tất cả. Schema JSON Draft 2020-12 nằm trong `schemas/`, luôn khớp
với model Pydantic.

Hai quy ước đáng nhắc: giá trị chưa biết để `null` chứ không điền mặc định cho đẹp; so sánh
phiên bản luôn qua `packaging.version.Version`, không bao giờ so chuỗi.

---

## 9. Phiên bản và alias

Mọi release PyPI đọc được đều chuẩn hoá theo PEP 440; khoá nào không đọc được thì báo ra chứ
không lặng lẽ bỏ. Alias chỉ liên kết khi nguồn nói rõ, cụm nào mơ hồ thì báo cáo. Và không
bao giờ tự suy ra phiên bản đã vá khi nguồn không hề đề cập — chỗ này chúng tôi cố tình cứng
nhắc, vì bịa một `fixed_version` là cách nhanh nhất để phá vỡ lòng tin vào cả cơ sở dữ liệu.

Kết quả live: `alias_resolution_rate = 1.00` với 57 alias và không cụm nào mơ hồ.
`version_coverage = 0.907`, tức 98 trên 108 phiên bản khớp được với tag Git hoặc commit; số
còn lại là các release rất cũ (0.2 đến đầu 1.x) đơn giản là không có tag tương ứng trên
GitHub.

---

## 10. Bằng chứng từ bản vá

21 bản ghi patch dựng từ commit chính thức, mỗi bản ghi giữ `commit_sha`, `parent_sha`, danh
sách file thay đổi, symbol thay đổi, guard mới thêm và regression test liên quan.
`patch_resolution_rate` và `fixed_release_verification_rate` đều bằng 1.00 — nghĩa là mọi
phiên bản được nêu là "đã vá" đều tồn tại thật trên PyPI, không có phiên bản ma.

Lấy CVE-2023-43804 (`GHSA-v845-jxx5-vc9f`) làm ví dụ, commit
`01220354d389cd05474713f8c982d05c9b17aafb`:

```text
File thay đổi:  src/urllib3/util/retry.py, test/test_retry.py,
                test/with_dummyserver/test_poolmanager.py, CHANGES.rst
Guard mới:      assert retry.remove_headers_on_redirect == {"authorization", "cookie"}
                assert "Cookie" not in data
Vá ở phiên bản: 1.26.17, 2.0.6
Độ tin cậy:     0.95 — "official repository commit with extracted diff evidence"
```

Mấy dòng guard rút từ diff chính là thứ phân biệt "đã nâng version" với "đã thật sự bịt lỗ":
nó cho biết sau bản vá thì hành vi nào mới được kiểm tra.

---

## 11. Security pattern được sinh ra sao

Thứ tự ưu tiên bằng chứng: khoảng có cấu trúc trước, rồi tới văn bản advisory, diff của bản
vá, regression test, cuối cùng mới đến changelog. Suy luận nào không có bằng chứng chống lưng
thì ghi thẳng vào `confidence.rationale` — ví dụ `"unsupported inference: changelog text not
supplied"`. Nếu sau này có thêm bản nháp do LLM sinh, nó vẫn không được phép sửa khoảng bị
ảnh hưởng đã có thẩm quyền.

19 pattern của lần crawl live phân bố như sau:

| `detection_type` | Số pattern | SAST cần gì để phán quyết |
|---|---|---|
| `version_api_dataflow` | 10 | version ∧ có gọi API ∧ có luồng dữ liệu không tin cậy |
| `version_api` | 4 | version ∧ có gọi API liên quan |
| `version_api_configuration_dataflow` | 2 | thêm cả điều kiện cấu hình rủi ro |
| `version_only` | 3 | chưa rút được điều kiện sử dụng, tạm chỉ dùng ở mức SCA |

Theo mức nghiêm trọng: 1 CRITICAL, 9 HIGH, 9 MODERATE.

Điểm hữu dụng trung bình cho SAST (`average_sast_usefulness_score`) là **0.816**. Ba pattern
`version_only` là thứ kéo con số này xuống: advisory tương ứng không kèm commit vá nên không
có gì để rút symbol ra.

---

## 12. Validate bắt được gì

Bước validate soi schema, sự có mặt của provenance, advisory canonical trùng nhau, và các
tín hiệu bất nhất. Lỗi nào cũng kèm `record_id` và lý do. Bật chế độ strict thì CLI trả exit
code 1.

Số liệu live từ `data/stats.json` và `data/validation_errors.json`:

| Chỉ số | Giá trị | Đọc thế nào |
|---|---|---|
| `provenance_coverage` | 1.000 | Bản ghi nào cũng lần được về byte gốc |
| `schema_validation_rate` | 1.000 | Không bản ghi nào lệch schema |
| `duplicate_rate` | 0.000 | Không có advisory canonical trùng |
| `alias_resolution_rate` | 1.000 | 57 alias, không cụm mơ hồ |
| `patch_resolution_rate` | 1.000 | 21/21 patch có bằng chứng diff |
| `fixed_release_verification_rate` | 1.000 | Phiên bản "đã vá" đều có thật trên PyPI |
| `version_coverage` | 0.907 | 98/108 phiên bản khớp tag hoặc commit |
| `range_resolution_rate` | **0.632** | 7/19 advisory có khoảng bất nhất, xem bên dưới |
| `average_sast_usefulness_score` | 0.816 | Bị 3 pattern `version_only` kéo xuống |

Validate bắt được **7 lỗi `contradictory_ranges`**, và cả 7 đều cùng một kiểu: phiên bản mà
advisory nói là "đã vá" lại nằm luôn trong tập phiên bản bị ảnh hưởng. Ví dụ với
CVE-2023-45803 (`GHSA-g4mx-q9vg-27p4`), `1.26.18` và `2.0.7` vừa là fixed version vừa xuất
hiện trong `affected_versions`.

Chúng tôi đã truy được nguyên nhân. Advisory OSV kèm theo một khoảng loại `GIT` chỉ có duy
nhất sự kiện `introduced: "0"`, không có `fixed`. Resolver mang khoảng đó đi chiếu lên danh
sách PyPI thì nó khớp cả 108 phiên bản, và phép hợp ở tầng advisory kéo theo cả những phiên
bản đã vá.

Điểm cần nói rõ: các khoảng `ECOSYSTEM` bên trong vẫn đúng. Với CVE-2023-45803,
`affected_ranges[].resolved` nêu chính xác `2.0.0`–`2.0.6` và `0.2`–`1.26.17`. Sai lệch chỉ
nằm ở trường tổng hợp `advisory.affected_versions`. Còn `security_pattern.version.resolved`
— thứ mà lệnh `query` thực sự dùng — vẫn cho kết quả đúng: truy vấn `2.4.0` thì CVE-2024-37891
trả về `Affected: no`, hoàn toàn hợp lý vì bản vá ở 2.2.2.

Nói cách khác, đây là tin xấu về dữ liệu nhưng là tin tốt về hệ thống: tầng validate làm đúng
việc của nó, chỉ thẳng vào chỗ cần sửa thay vì để lỗi âm thầm đi vào phán quyết.

---

## 13. Chạy live thì gặp gì

Có ba lỗi mà chỉ dữ liệu thật mới lộ ra. Cả ba đã sửa kèm test hồi quy.

**Không đọc `.env`.** CLI chỉ gọi `os.getenv`, nên `GITHUB_TOKEN` để trong `.env` bị bỏ qua
hoàn toàn và lần crawl đầu tiên đụng ngay rate limit của GitHub. Đã thêm
`crawler/utils/envfile.py` để nạp các khoá trong allowlist (`GITHUB_TOKEN`, `NVD_API_KEY`,
`CRAWLER_OFFLINE`) lúc import CLI. Biến môi trường của shell vẫn thắng, và giá trị token thì
không bao giờ được in ra.

**Tag trùng khi map version.** Repo thật có cả `v2.0.5` lẫn `2.0.5` trỏ về cùng một release,
làm `map_tags_to_versions` báo lỗi rồi dừng. Giờ nó giữ tag ưu tiên — dạng có `v` đứng trước
dạng thuần số — thay vì bỏ cuộc.

**`fixed` của OSV lại là commit SHA.** Với khoảng loại `GIT`, `fixed` chứa hash commit chứ
không phải số phiên bản; nhét vào `fixed_versions` thì Pydantic báo lỗi PEP 440 ngay. Đã tách
ra: chỉ giá trị hợp PEP 440 mới vào `events` và `fixed_versions`, còn commit SHA đi vào
`patch_commits`.

Ngoài ra lệnh `run` giờ bắt thêm `ValueError` và `OSError` để báo lỗi cho gọn thay vì đổ cả
traceback vào mặt người dùng. Cả nhóm sửa này nằm ở
[PR #13](https://github.com/longngx04/urllib3_knowledge_crawler/pull/13).

---

## 14. Ba ca cụ thể, lấy từ dữ liệu live

### A. Giải nén khi streaming — CVE-2025-66471

```text
Advisory:        GHSA-2xpw-w6gg-jr37 (CVE-2025-66471, PYSEC-2026-1994)
Mức / CWE:       HIGH / CWE-409 (khuếch đại dữ liệu nén)
CVSS 4.0:        AV:N/AC:L/AT:P/PR:N/UI:N/VC:N/VI:N/VA:H/SC:N/SI:N/SA:H
Bị ảnh hưởng:    1.0 → 2.5.0, vá ở 2.6.0 — 98 phiên bản trong danh sách
Module:          urllib3.response
Symbol chính:    ContentDecoder, DeflateDecoder, _decode, _decompress, _get_decoder
Tiền đề:         gọi API streaming (stream(), read(amt=...), read1(), read_chunked(),
                 readinto()) trên response nén, và không tắt decoding
Luồng dữ liệu:   dữ liệu không tin cậy → API dễ tổn thương
An toàn khi:     đã ở 2.6.0 trở lên
Bằng chứng:      commit c19571de34c47de3a766541b041637ba5f716ed7
Regression test: test/test_response.py
Khắc phục:       nâng lên ≥ 2.6.0, kèm Brotli ≥ 1.2.0 nếu đang dùng extra brotli
Dương tính giả:  chỉ import urllib3 mà không stream nội dung nén
Phán quyết:      version trong khoảng ∧ có gọi API streaming ∧ nội dung từ nguồn không tin cậy
```

Đây là ví dụ gọn nhất cho luận điểm của cả dự án. "Đang dùng 2.4.0" tự nó chưa nói lên điều
gì; ứng dụng chỉ thật sự rủi ro khi đọc theo chunk dữ liệu nén đến từ nguồn không tin cậy.

### B. Rò `Proxy-Authorization` khi redirect — CVE-2024-37891

```text
Advisory:        GHSA-34jh-p97f-mpxf (CVE-2024-37891, PYSEC-2026-1995)
Mức / CWE:       MODERATE / CWE-669 (chuyển tài nguyên sai miền tin cậy)
Vá ở:            1.26.19 cho nhánh 1.x, 2.2.2 cho nhánh 2.x
Tiền đề:         đang dùng ProxyManager hoặc proxy HTTP(S) ∧ ứng dụng đi theo redirect
Luồng dữ liệu:   redirect_location_header → trình xử lý redirect
Module:          urllib3.util.retry (remove_headers_on_redirect)
An toàn khi:     ≥ 2.2.2, hoặc ≥ 1.26.19 nếu còn ở nhánh 1.x
Bằng chứng:      commit accff72ecc2f6cf5a76d9570198a93ac7c90270e
Regression test: test/test_retry.py, test/with_dummyserver/test_poolmanager.py
Kiểm chứng:      query 2.4.0 → "Affected: no", đúng vì 2.4.0 > 2.2.2
```

Ca này lộ ra một hạn chế thật của bản hiện tại. Pattern chỉ chọn **một** nhánh
`fixed_versions` để đưa vào khuyến nghị, nên `upgrade_guidance` ghi "nâng lên 1.26.19 hoặc
mới hơn" trong khi `negative_conditions` lại nói "≥ 2.2.2". Ai đang ở nhánh 2.x mà làm theo
lời khuyên đó thì đi lùi. Cách đúng là xuất khuyến nghị riêng cho từng nhánh bảo trì — xem
mục 16.

### C. Redirect bị bỏ qua trên Emscripten — CVE-2025-50182

```text
Advisory:        GHSA-48p4-8xcf-vxj5 (CVE-2025-50182, PYSEC-2026-1997)
Mức / CWE:       MODERATE / CWE-601 (redirect tới đích không tin cậy), có dấu hiệu SSRF
Bị ảnh hưởng:    2.2.0 → 2.4.0, vá ở 2.5.0 — chỉ 6 phiên bản, khoảng rất gọn
Module:          urllib3.contrib.emscripten.fetch
Tiền đề:         chạy trên Pyodide/Emscripten ∧ ứng dụng đi theo redirect
Luồng dữ liệu:   redirect_location_header → trình xử lý redirect
An toàn khi:     ≥ 2.5.0
Bằng chứng:      commit 7eb4a2aafe49a279c29b6d1f0ed0f42e9736194f
Regression test: test/contrib/emscripten/test_emscripten.py
Dương tính giả:  backend Python thuần, không chạy trong môi trường Emscripten
```

Ca này cho thấy giá trị của điều kiện API rõ nhất: một service server-side dùng 2.3.0 gần
như chắc chắn *không* bị ảnh hưởng, vì lỗi nằm trong nhánh `contrib.emscripten`. Nếu chỉ so
version thì đây là một cảnh báo sai được gửi cho toàn bộ người dùng 2.2–2.4.

Lệnh dùng cho cả ba ca trên:

```bash
python -m crawler query --package urllib3 --version 2.4.0 --output data
```

---

## 15. Chạy lại có ra đúng kết quả cũ không

Có, và đây là thứ chúng tôi giữ khá chặt.

Output JSONL sắp thứ tự xác định, nên input giống nhau thì `record_id` và nội dung giống
nhau. Nhờ vậy diff giữa hai lần crawl là diff về nghĩa, không phải nhiễu do thứ tự dòng.

`data/manifest.json` lưu SHA-256 của từng file xuất ra, muốn kiểm tra toàn vẹn thì không cần
chạy lại pipeline. `data/raw/` là cache theo nội dung, nên `--skip-crawl` cho phép chạy lại
mọi bước từ chuẩn hoá trở về sau mà không gọi mạng.

Bộ test mặc định có **244 test**, chạy trên Python 3.12.3 và hoàn toàn offline; phần kiểm
tra tính xác định nằm ở `tests/test_deterministic_pipeline.py`. Ở lần cập nhật này chúng tôi
đã chạy `pytest` (244 passed), `ruff check`, `ruff format --check` và `mypy crawler` — tất cả
sạch.

---

## 16. Còn dở ở đâu

Xếp theo mức ảnh hưởng tới chất lượng phán quyết:

1. **Khoảng `GIT` mở làm phình `advisory.affected_versions`.** 7 trong 19 advisory bị,
   `range_resolution_rate` vì thế chỉ còn 0.632. Hướng sửa: đừng chiếu khoảng loại `GIT` lên
   danh sách PyPI, hoặc bỏ qua nó khi advisory đã có khoảng `ECOSYSTEM`. Đây là việc nên làm
   đầu tiên.
2. **Rút symbol từ diff còn nhiễu.** Việc rút dựa trên regex và gán tên hàm test cho module
   nguồn, nên sinh ra những symbol vô nghĩa kiểu
   `urllib3.util.retry.test_retry_set_remove_headers_on_redirect` hay
   `urllib3.response.git_clone`. Hướng sửa: tách symbol theo file gốc — `src/` khác `test/` —
   và không suy tên module từ file test.
3. **Khuyến nghị nâng cấp không theo nhánh bảo trì.** Như ca B: vá trên cả 1.x và 2.x nhưng
   `upgrade_guidance` chỉ nêu một nhánh.
4. **Ba pattern `version_only`.** Advisory không kèm commit vá nên không rút được điều kiện
   sử dụng. Chúng chỉ nên dùng ở mức SCA cho tới khi có bằng chứng patch.
5. **Endpoint dạng list của GitHub hiện chỉ lấy trang đầu** nếu không mở rộng, nên 0.907 chưa
   phải trần thật của `version_coverage`.
6. **Rút symbol không phải phân tích liên thủ tục.** Nó nói cho engine biết *nên tìm gì*,
   không thay thế được data-flow analysis.
7. **Nhánh NVD vẫn để ngỏ.** CWE và CVSS hiện lấy từ OSV.

---

## 17. Đổi sang thư viện khác thì làm gì

Thêm `configs/<package>.yaml` khai báo package, repo và nguồn cần bật. Tầng retrieval, model,
resolver, exporter và CLI dùng lại nguyên vẹn, không phải sửa code lõi. Chỉ cần chỉnh
heuristic đọc changelog và commit nếu repo mới có quy ước khác — `urllib3` dùng
`CHANGES.rst`.

Một lưu ý: chạy lại validate và thống kê **trước khi** công bố độ phủ. Mọi con số ở mục 12
chỉ đúng cho `urllib3`.

---

## 18. Rút ra được gì

**Đi hết một đường dọc trước khi mở rộng bề rộng.** Cách làm vertical slice khiến các lỗ
trong hợp đồng dữ liệu lộ ra sớm, lúc sửa còn rẻ.

**Fixture không thay được dữ liệu thật.** Bộ test offline xanh 100%, vậy mà crawl live vẫn
lộ ba lỗi: tag trùng, commit SHA nằm trong `fixed`, và `.env` không được đọc. Fixture chứng
minh logic đúng; chỉ dữ liệu thật mới chứng minh giả định đúng.

**Validate ồn ào tốt hơn validate im lặng.** 7 lỗi `contradictory_ranges` nghe như thất bại,
nhưng chúng chỉ đúng chỗ cần sửa. Nếu tầng validate dễ tính hơn, lỗi đó sẽ lặng lẽ đi vào
kết quả phán quyết và không ai biết.

**Tách khoảng SCA khỏi điều kiện sử dụng của SAST là insight cốt lõi.** Gần như mọi giá trị
còn lại của hệ thống đều mọc ra từ ranh giới đó.

**`--offline --fixture-dir` là bắt buộc, không phải tiện lợi.** Không có nó thì không thể
chứng minh cả pipeline mà không lệ thuộc mạng, và CI sẽ đỏ vì rate limit chứ không vì code.

---

## 19. Chốt lại

Chọn `urllib3` cho phép làm một bản pilot trọn vẹn và có bằng chứng thật: crawl từ nguồn có
thẩm quyền, giữ provenance đến từng byte, giải đúng những phiên bản bị ảnh hưởng, và gắn kèm
điều kiện API, cấu hình, luồng dữ liệu mà SAST cần. Trên dữ liệu thật, hệ thống sinh 19
security pattern, trong đó 16 pattern có điều kiện sử dụng cụ thể — nghĩa là phần lớn phát
hiện có thể được thu hẹp vượt hẳn mức so-version.

Phần còn dở cũng nói thẳng: khoảng `GIT` mở làm 7 advisory có tập phiên bản bị ảnh hưởng
phình ra ở tầng tổng hợp, và việc rút symbol còn lẫn tên hàm test. Cả hai đều đã khoanh được
nguyên nhân và có hướng sửa cụ thể ở mục 16. Nền provenance, tính xác định và cổng validate
đã đủ chắc để những cải thiện sắp tới được đo bằng số, không phải đoán.
