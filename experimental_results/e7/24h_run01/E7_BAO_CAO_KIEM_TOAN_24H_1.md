# BÁO CÁO KẾT QUẢ THÍ NGHIỆM E7

**Tên thí nghiệm:** Quan sát vận hành dài hạn của phân hệ  
**Mã lượt chạy:** `E7_24H_20260921_RUN01`  
**Hình thức:** Phát lại cảnh báo lịch sử có kiểm soát qua Elasticsearch vào phân hệ SOAR  
**Thời gian:** Từ 15:00:44 ngày 21/09/2026 đến 15:00:44 ngày 22/09/2026 (giờ Việt Nam)  
**Thời lượng quan sát:** 24 giờ

## 1. Mục đích và phương pháp

Thí nghiệm E7 quan sát khả năng duy trì tiếp nhận cảnh báo, tạo bản ghi sự cố và xử lý hàng đợi của phân hệ SOAR trong một lượt phát lại kéo dài 24 giờ. Dữ liệu đầu vào là các bản ghi cảnh báo lịch sử có nguồn gốc từ E6, được phát lại có kiểm soát vào Elasticsearch. Bộ quan sát thu thập số liệu vận hành theo chu kỳ một phút; kết quả được lưu trong nhật ký, các bảng quan sát, manifest phát lại và cơ sở dữ liệu SQLite.

Thí nghiệm sử dụng **288 bản ghi phát lại**, gồm **159 bản ghi PortScan và 129 bản ghi Exploit**, được chọn từ sáu phiên E1 Test thuộc hai kịch bản Scan và Exploit. Đây là **288 bản ghi cảnh báo được phát lại**, không được diễn giải là 288 phiên tấn công độc lập.

## 2. Kết quả quan sát được

### 2.1. Thời gian quan sát và khối lượng xử lý

Bộ quan sát hoạt động đủ **24 giờ** và lưu **1.441 mẫu theo phút**. Khoảng cách lấy mẫu tối đa được ghi nhận là 60 giây; các lần đọc cơ sở dữ liệu tại thời điểm lấy mẫu đều thành công.

Manifest phát lại ghi nhận **288/288** bản ghi được tạo trong index đích. Đối chiếu manifest với bản sao SQLite cho thấy cả 288 mã bản ghi phát lại đều có bản ghi tương ứng trong hàng đợi và bảng sự cố.

### 2.2. Số lượng và tỷ lệ cảnh báo/sự cố

- **Tổng số cảnh báo phát lại:** 288.
- **Tổng số bản ghi sự cố được tạo:** 288.
- **Số cảnh báo trung bình:** 288 / 24 = **12 cảnh báo/giờ**.
- **Số sự cố trung bình:** 288 / 24 = **12 sự cố/giờ**.
- **Tỷ lệ cảnh báo : sự cố trong lượt phát lại:** **288 : 288 = 1 : 1**.

Các giá trị **12 cảnh báo/giờ** và **12 sự cố/giờ** là *trung bình của toàn bộ 24 giờ*, không phải số đo chi tiết riêng của từng giờ. Tỷ lệ 1:1 phản ánh việc tạo bản ghi sự cố trong pipeline phát lại; không phải chỉ tiêu độ chính xác phát hiện của NIDS.

### 2.3. Hành vi hàng đợi và lỗi được ghi nhận

Tại thời điểm kết thúc, **288/288 bản ghi hàng đợi** có trạng thái `DONE`. Trong bản sao dữ liệu đã lưu, không có bản ghi hàng đợi ở trạng thái `DEAD`, không ghi nhận lần thử lại và không có nội dung `last_error` đối với 288 bản ghi này.

Trong **1.441 mẫu quan sát** đã lưu, không ghi nhận lỗi đọc cơ sở dữ liệu. Bản sao SQLite đạt kết quả `PRAGMA integrity_check = ok`.

**Ý nghĩa của `DONE`:** Sự kiện đã được phân hệ SOAR tiêu thụ khỏi hàng đợi và tạo bản ghi sự cố; trạng thái này không tự xác nhận việc phê duyệt hoặc thực thi hành động ứng phó đã hoàn tất.

### 2.4. Lưu trữ và khả năng đối chiếu

Bộ bằng chứng E7 được bảo quản trong gói `E7_FINAL_BACKUP_20260922.tar.gz`, gồm dữ liệu đầu vào đã lưu, manifest phát lại, mã chạy phát lại, nhật ký SOAR, nhật ký observer, các bảng quan sát và bản sao SQLite nhất quán. Báo cáo kiểm toán bổ sung ghi nhận **288/288** mã băm của tài liệu nguồn trùng khớp với dữ liệu được khôi phục để đọc; bản lưu nguồn không bị ghi đè.

## 3. Kết luận và những thiếu sót cần ghi nhận

**Kết luận trong phạm vi đã thực hiện:** E7 đã hoàn thành lượt phát lại cảnh báo có kiểm soát kéo dài **24 giờ**. Trong cấu hình thí nghiệm này, phân hệ SOAR đã tiếp nhận 288 cảnh báo, tạo 288 bản ghi sự cố và đưa 288/288 sự kiện hàng đợi đến trạng thái `DONE`. Bộ quan sát lưu 1.441 mẫu theo phút; không ghi nhận lỗi hàng đợi hoặc lỗi đọc cơ sở dữ liệu tại các thời điểm quan sát. Kết quả chứng minh khả năng duy trì tiếp nhận và tiêu thụ hàng đợi của phân hệ SOAR **trong điều kiện phát lại đã cấu hình**.

**Trạng thái báo cáo:** Hoàn thành **lượt quan sát và phát lại 24 giờ**; các nội dung chưa được đo hoặc chưa được xác nhận được công bố như những thiếu sót của thí nghiệm, không được trình bày thành kết quả đã kiểm chứng.

