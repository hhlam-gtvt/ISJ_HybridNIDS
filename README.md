## Giới thiệu

Repository dự kiến kết hợp hai phân hệ nghiên cứu:

- **Hybrid-NIDS — phân hệ phát hiện:** xử lý lưu lượng mạng và phát hiện xâm nhập bằng NFStream, Random Forest và Suricata.
- **Orchestrator–ELK–LLM — phân hệ sau cảnh báo:** tiếp nhận cảnh báo, điều phối sự cố, đánh giá chính sách, hỗ trợ phân tích bằng LLM khi phù hợp, thực hiện hoặc không thực hiện phản ứng theo các cơ chế kiểm soát an toàn, ghi nhật ký và lập báo cáo.

Mục tiêu tích hợp là chuyển dữ liệu đầu ra của Hybrid-NIDS tới bộ điều phối cảnh báo (Orchestrator) thông qua Logstash/Elasticsearch. **mã nguồn không tự chứng minh hệ thống đã vận hành end-to-end hoặc tất cả thực nghiệm đã tái lập được.** Các khẳng định đó phải dựa trên kiểm thử và bằng chứng tương ứng.

 **Sơ đồ kiến trúc **
```text
    Lưu lượng phòng thí nghiệm / replay
                  |
                  v
Hybrid-NIDS: NFStream + Random Forest / Suricata
                  |
                  v
      Logstash / Elasticsearch
                  |
                  v
Orchestrator -> Policy / Rule Engine -> RAG / LLM (khi áp dụng)
                  |
                  v
Phê duyệt / kiểm soát phản ứng -> Hành động hoặc không hành động
                  |
                  v
             Audit / PDF / Dashboard
```

## Cấu trúc repository 

```text
hybrid-nids-soar-elk-llm/
├── README.md
├── LICENSE                       # Chờ xác nhận giấy phép
├── CITATION.cff                  # Dự kiến: metadata trích dẫn đã xác minh
├── .gitignore
├── .env.example                  # Chỉ chứa giá trị mẫu, không chứa bí mật
├── requirements.txt              # Môi trường phát hành đã kiểm chứng
│
├── detector/
│   └── hybrid-nids/              # Mã nguồn và tài liệu phân hệ Cường
├── response/
│   └── soar-elk-llm/             # Mã nguồn và kiểm thử phân hệ Lam
├── integration/                  # Dự kiến: schema cảnh báo và lớp kết nối
├── configs/                      # Cấu hình ELK/triển khai đã loại bỏ bí mật
│
├── experiments/
│   ├── e1/
│   ├── e2/
│   ├── e3/
│   ├── e4/
│   ├── e5/
│   ├── e6/
│   └── e7/
│
├── analysis/
│   ├── make_generated.py
│   ├── e2_scenario_table.py
│   ├── e2_score_figure.py
│   ├── e5_agreement.py
│   ├── e6_supplementary_check.py
│   └── overlap_shingles.py
│
├── reproducibility/              # Dự kiến: manifest dữ liệu, kết quả và lệnh chạy
├── docs/                         # Kiến trúc, protocol, giới hạn, đạo đức nghiên cứu
└── publication/                  # Thông tin công bố và các tuyên bố đã xác minh
```

## Thực nghiệm và bằng chứng E1–E7

| Thực nghiệm | Bằng chứng nêu trong bản thảo | Phạm vi và giới hạn cần công bố |
| --- | --- | --- |
| **E1** | Manifest session, ground truth, sự kiện và checksum | PCAP và log gốc phải được xem xét riêng trước khi phát hành. |
| **E2** | Nguồn gốc mô hình (*model lineage*) và chỉ số | Tệp xuất dự đoán E2.
| **E3** | Session và so sánh định tuyến | Giới hạn môi trường/ruleset. |
| **E4** | Bảng xuất tổng hợp và no-action replay | Hành vi phản ứng/không phản ứng của các chế độ thực sự đã chạy. |
| **E5** | Mô hình, chỉ số tự động, ánh xạ case và bảng điểm mù của reviewer | JSON/schema; lưu rubric và bằng chứng. |
| **E6** | Bảng kết quả, hồ sơ phần cứng/đồng hồ và bằng chứng supplementary replay | amendment, raw run và giới hạn. |
| **E7** | Observer pilot; verified summary và tài liệu nguồn lượt chạy 24 giờ; replay, incident| Endurance **replay** và post-run. |

Môi trường chạy: **Python 3.10.12, pandas 2.3.3, NumPy 2.2.6, Matplotlib 3.10.9**.



