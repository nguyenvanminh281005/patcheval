Ok, CVE patching với custom loop — vậy đây là dạng agent: đọc advisory/PoC → xác định vị trí lỗi trong code → sinh patch → verify (build + re-run PoC) → retry nếu fail. Vài điểm đáng cân nhắc khi ghép với OpenRouter free model:

**Chọn model theo từng bước trong loop** (đừng dùng 1 model cho tất cả):
- **Bước phân tích** (đọc CVE description, trace stack, khoanh vùng file/hàm lỗi): cần reasoning tốt → `openai/gpt-oss-120b:free`.
- **Bước sinh patch** (viết diff cụ thể): cần model hiểu code tốt → thử `qwen/qwen3-coder:free` nếu còn free, so sánh chất lượng với gpt-oss-120b trên vài CVE mẫu trước khi chốt.
- **Bước phụ** (parse log, extract CVE ID, tóm tắt build error): dùng model nhẹ `gpt-oss-20b:free` để tiết kiệm rate limit cho 2 model chính.

**Vấn đề cụ thể với loop tự retry:**
1. **Rate limit là nút thắt lớn nhất** — nếu loop generate→build→test→retry chạy vài chục vòng cho 1 CVE, free tier 20 req/phút sẽ hết rất nhanh. Nên:
   - Cache/dedupe request giống nhau (đừng gửi lại toàn bộ context mỗi lần nếu chỉ error message thay đổi).
   - Set max retry cứng (vd 5-8 lần) rồi escalate sang model trả phí hoặc báo human review, đừng để loop free-tier chạy vô hạn.
2. **Patch không compile / không match hunk**: model free hay lệch context line number khi sinh diff. Nên bắt agent sinh patch dạng search-replace theo function signature thay vì diff format cứng theo line number — dễ apply hơn, ít lỗi hunk mismatch.
3. **Feedback loop cho retry**: khi build/test fail, đừng chỉ nhét raw stderr vào lại — tóm tắt lỗi (dùng model nhẹ) trước khi đưa vào context của model sinh patch, giữ context gọn để tránh out-of-context và giảm token cho free tier.
4. **Verify PoC thật sự pass**: đảm bảo loop chạy PoC lại sau patch, không chỉ tin "build thành công" — false positive rất dễ xảy ra nếu chỉ check compile.
