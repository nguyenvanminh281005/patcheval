Quan trọng hơn: **PatchEval không phải kiểu “đưa dataset vào LLM rồi nhận accuracy”**. Pipeline của nó đại khái là:

```text
Go CVE dataset
      ↓
LLM / Agent
      ↓
Generate patch
      ↓
Patch được ghi vào repo
      ↓
Docker sandbox
      ↓
PoC test
      ↓
Unit test
      ↓
PatchEval ghi kết quả
```

Nên chỉ cần **một mắt xích không tương thích** là cậu có thể thấy tình trạng:

> chạy rất lâu → không có result / output rỗng / model không trả lời / Docker không verify được / cuối cùng tưởng là “model không chạy”.

### Tớ nghi nhất 4 vấn đề

**1. Model free của cậu chưa thật sự tương thích với PatchEval**

PatchEval mặc định cần cấu hình:

```text
model_name
api_key
api_url
model
```

và chạy thông qua `exp_llm.main`. ([GitHub][2])

Nếu cậu dùng model free thông qua OpenRouter/Gemini/Ollama/endpoint khác thì phải kiểm tra **API format mà PatchEval đang gọi có tương thích với endpoint đó hay không**.

Đây là điểm tớ nghi rất cao.

---

**2. Model local/free quá yếu đối với task này**

Cái này rất quan trọng.

PatchEval không chỉ yêu cầu:

> "hãy sửa đoạn Go code này"

Mà model phải hiểu vulnerability → tìm nguyên nhân → sinh patch → patch phải compile → vượt PoC → và trong setting đầy đủ còn phải vượt unit test.

Ngay cả những model mạnh cũng không phải task dễ. Bảng kết quả chính thức của PatchEval cho thấy tỷ lệ verified của các hệ thống hàng đầu chỉ ở mức vài chục phần trăm, và Go còn thấp hơn Python/Node ở nhiều cấu hình. ([PatchEval][1])

Vì vậy nếu cậu đang dùng kiểu:

```text
6GB VRAM
↓
model local nhỏ
↓
PatchEval Go
↓
full dataset
```

thì **không thể kỳ vọng nó chạy giống GPT-5/Gemini Pro trong paper**.

Nhưng vẫn có thể làm thực nghiệm — chỉ cần thiết kế experiment hợp lý.

---

**3. Cậu có thể đang chạy quá nhiều case ngay từ đầu**

Đây là lỗi tớ muốn cậu kiểm tra **ngay**.

Đừng chạy:

```bash
input.json
→ toàn bộ Go dataset
```

mà hãy thử:

```text
1 CVE
↓
1 model
↓
1 epoch
↓
xem model có generate patch không
↓
xem patch có được ghi ra không
↓
xem Docker verify không
```

Nếu **1 case chạy thành công**, mới tăng lên:

```text
5 cases
↓
20 cases
↓
50 cases
↓
full Go dataset
```

Như vậy cậu sẽ biết chính xác nó chết ở đâu.

---

**4. Agent chọn model của cậu có thể đang chọn sai “model phù hợp” với task**

Cái này đặc biệt đáng chú ý vì cậu nói cậu đã **tạo agent để lựa model**.

Nếu agent chỉ đánh giá kiểu:

```text
Model A → coding benchmark tốt
Model B → reasoning tốt
Model C → miễn phí
```

thì chưa đủ.

Với PatchEval, model cần tối thiểu:

```text
Code understanding
        +
Vulnerability reasoning
        +
Long-context
        +
Code generation
        +
Instruction following
        +
Stable API
        +
Output format consistency
```

Đặc biệt với Go vulnerability repair, **model coding benchmark cao chưa chắc patch vulnerability tốt**.

---

### Nhưng tớ chưa muốn đoán mò lỗi của cậu

Tớ nghĩ cách tốt nhất là **debug pipeline của cậu từ đầu đến cuối**.

Cậu gửi cho tớ **4 thứ này**:

```text
1. Lệnh cậu dùng để chạy PatchEval
2. File API-ENV.json của cậu
   → che API KEY lại
3. Log terminal từ lúc bắt đầu chạy
   → khoảng 50-100 dòng cuối là được
4. Model mà agent của cậu đang chọn
```

Nếu có thì gửi thêm:

```text
5. Cấu hình máy:
   CPU:
   RAM:
   GPU:
   VRAM:
   OS:
   
6. Cậu đang dùng:
   Ollama / Gemini API / OpenRouter / HuggingFace / cái khác?
```

**Đừng gửi API key thật.**

Sau đó tớ có thể đi cùng cậu theo đúng pipeline:

```text
                    PatchEval
                       │
             ┌─────────▼─────────┐
             │   Go dataset      │
             └─────────┬─────────┘
                       │
                       ▼
                Model / Agent
                       │
                ❌ ← lỗi ở đâu?
                       │
                       ▼
                 Patch output
                       │
                       ▼
                 Docker sandbox
                       │
                  ┌────┴────┐
                  ▼         ▼
                 PoC      Unit Test
                  │         │
                  └────┬────┘
                       ▼
                    Result
```

Tớ sẽ giúp cậu xác định **chính xác nó đang fail ở tầng nào**, rồi sau đó mới chọn model free phù hợp. Làm vậy sẽ tốt hơn nhiều so với việc cứ đổi model rồi chạy lại.
