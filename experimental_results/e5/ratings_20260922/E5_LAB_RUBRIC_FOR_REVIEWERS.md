# E5 – rubric dùng cho hai reviewer độc lập (LAB_SURICATA_ONLY)

Đơn vị chấm: mỗi `blind_id` là một bản tư vấn. Mỗi reviewer chấm độc lập cùng 210 `blind_id` ở thứ tự xáo trộn; không xem chế độ, repetition, crosswalk, schema validity, hay điểm của reviewer còn lại. Đối chiếu `case_ref` với `REFERENCE_30_CASES_FOR_BOTH_REVIEWERS.csv` và yêu cầu log/PCAP đầy đủ nếu đoạn trích chưa đủ. Nhãn GT là dữ liệu lab tham chiếu, KHÔNG được đưa vào prompt.

| Tiêu chí (1–5) | 1 | 2 | 3 | 4 | 5 |
|---|---|---|---|---|---|
| Factual correctness (cao tốt) | Nhận định quan trọng trái dữ kiện | Nhiều nhận định thiếu căn cứ | Chủ yếu phù hợp, chưa tách rõ quan sát/suy luận | Hầu hết chính xác và nêu giới hạn | Mọi nhận định quan trọng đều kiểm chứng được với dữ kiện đã cung cấp |
| Traceability (cao tốt) | Không lần ra được nguồn | Nguồn rất mơ hồ | Có một số tham chiếu nguồn cụ thể | Đa số kết luận truy vết được | Mọi kết luận quan trọng đều trỏ tới bằng chứng reviewer có thể kiểm tra |
| Actionability (cao tốt) | Khuyến nghị sai/nguy hiểm | Khuyến nghị mơ hồ, thiếu điều kiện an toàn | Bước xác minh cơ bản | Hướng dẫn kiểm tra cụ thể, an toàn | Bước tiếp theo rõ, ưu tiên hợp lý, nêu khi nào cần dừng/thu thập thêm bằng chứng |
| Workload (THẤP tốt) | Hầu như không phải sửa/tra thêm | Cần sửa/tra ít | Cần sửa/tra ở mức vừa | Cần kiểm tra hoặc viết lại nhiều | Gần như phải tạo lại tư vấn từ đầu |

**Workload đo công sức ước tính để đọc, kiểm tra và chỉnh sửa tư vấn**, không phải thời gian SOC thực đo. Điểm 1 là ít công sức hơn, 5 là nhiều công sức hơn. Chỉ chấm được khi có đủ căn cứ; nếu không, để trống điểm và giải thích trong `reviewer_notes`. Không điền điểm thay cho reviewer, không đoán nội dung đầu ra rỗng. Giữ nguyên cả đầu ra sai schema và tham chiếu sai bằng chứng. Có thể nhận ra loại đầu ra từ văn phong; nếu reviewer đoán được mode, ghi như giới hạn của blinding.

Rubric này có thể sử dụng để chấm cohort lab hiện có; phiếu pilot có rubric khác không được ghép làm điểm main. Việc dùng lại cùng cohort sau pilot không tạo ra kiểm chứng Test độc lập. Trước khi gửi phiếu, hai reviewer cần nhận **cùng** rubric này và xác nhận chiều điểm workload.
