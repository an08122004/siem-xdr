# Nguồn dataset (sinh bởi tools/fetch_datasets.py)

Cập nhật: 2026-09-26T17:49:31+00:00

| Dataset | File | Phiên bản | Kích thước | SHA-256 | Giấy phép | Dùng cho |
|---|---|---|---|---|---|---|
| [HTTP DATASET CSIC 2010 (anomalous test)](https://www.tic.itefi.csic.es/dataset/) | [`csic2010-anomalousTrafficTest.txt`](https://raw.githubusercontent.com/msudol/Web-Application-Attack-Datasets/master/OriginalDataSets/csic_2010/anomalousTrafficTest.txt) | master | 15.7 MB | `12fa4f0d496ceb85…` | Dữ liệu công bố cho nghiên cứu bởi CSIC (Tây Ban Nha); mirror trong repo GPL-3.0 msudol/Web-Application-Attack-Datasets | Request HTTP bất thường (có nhãn) -> mẫu DƯƠNG cho rule Web |
| [HTTP DATASET CSIC 2010 (normal test)](https://www.tic.itefi.csic.es/dataset/) | [`csic2010-normalTrafficTest.txt`](https://raw.githubusercontent.com/msudol/Web-Application-Attack-Datasets/master/OriginalDataSets/csic_2010/normalTrafficTest.txt) | master | 20.2 MB | `f05dfc312d5d14fd…` | như trên | Request HTTP bình thường (có nhãn) -> đo báo nhầm của rule Web / rule AI đề xuất |
| [SigmaHQ rules](https://github.com/SigmaHQ/sigma) | [`sigma_all_rules.zip`](https://github.com/SigmaHQ/sigma/releases/download/r2026-07-01/sigma_all_rules.zip) | r2026-07-01 | 3.2 MB | `5725c91b5813587a…` | Detection Rule License (DRL) 1.1 — được dùng, phải ghi nguồn tác giả rule | Kho rule phát hiện cộng đồng -> tài liệu tham khảo (RAG) cho AI khi đề xuất rule mới |
