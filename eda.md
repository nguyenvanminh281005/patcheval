# 5. EDA mình nghĩ bạn nên làm

Nếu mục tiêu của bạn là **nghiên cứu PATCHEVAL**, mình sẽ chia thành 4 tầng:

### EDA Level 1 — Dataset Overview

```text
# CVEs
# repositories
# languages
# CWEs
CVE year distribution
```

Visual:

* Bar chart: CVE theo language
* Bar chart: CWE distribution
* Line chart: CVE theo year
* Treemap: CWE → language

---

### EDA Level 2 — Vulnerability Characteristics

```text
CWE
Language
Year
Repository
```

Phân tích:

```text
CWE × Language
CWE × Year
Language × Year
```

Ví dụ:

```text
             Python   Go   JS
CWE-79          50    10   80
CWE-89          30    20   40
CWE-22          40    50   30
```

Cái này có thể cho bạn insight về **vulnerability landscape**.

---

### EDA Level 3 — Patch Complexity

Đây là phần mình thấy **có giá trị nghiên cứu nhất**.

Phân tích:

```text
patch_lines
patch_hunks
patch_files
```

Ví dụ:

```text
Patch Complexity
│
├── Easy
│    1–5 lines
│
├── Medium
│    5–20 lines
│
├── Hard
│    20–50 lines
│
└── Very Hard
     50+ lines
```

Sau đó cross-tab:

```text
CWE × Patch Complexity
Language × Patch Complexity
Year × Patch Complexity
```

Paper cũng dùng chính **lines / hunks / files** để phân nhóm độ phức tạp patch và đánh giá khả năng repair của LLM. 

---

### EDA Level 4 — LLM Repair Difficulty

Nếu bạn có kết quả benchmark của LLM, đây mới là EDA rất mạnh:

```text
CVE
│
├── CWE
├── Language
├── Patch complexity
├── Repository size
├── Vulnerability localization
└── LLM success/failure
```

Sau đó tìm:

```text
P(repair success | CWE)
P(repair success | language)
P(repair success | patch size)
P(repair success | localization precision)
```

Ví dụ insight:

> LLMs perform significantly worse on vulnerabilities requiring multi-file modifications than on single-file patches.

Hoặc:

> Vulnerabilities involving larger patch scopes exhibit lower repair success rates.

Đây sẽ chuyển EDA từ **"dataset có gì"** thành **"yếu tố nào ảnh hưởng đến khả năng LLM sửa vulnerability"**.
