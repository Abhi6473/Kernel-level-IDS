# 📥 CIC-IDS-2017 Dataset Download

[![Direct Download](https://img.shields.io/badge/Direct_Download-MachineLearningCSV.zip_(230_MB)-blue?style=for-the-badge&logo=icloud)](http://205.174.165.80/CICDataset/CIC-IDS-2017/Dataset/MachineLearningCSV.zip)
[![Official UNB Portal](https://img.shields.io/badge/Official_Portal-UNB_CIC--IDS--2017-green?style=for-the-badge)](https://www.unb.ca/cic/datasets/ids-2017.html)
[![Kaggle Mirror](https://img.shields.io/badge/Kaggle-Mirror-orange?style=for-the-badge&logo=kaggle)](https://www.kaggle.com/datasets/cicdataset/cicids2017)

### 🔗 Direct Download Links:
- 📦 **[Direct Download: MachineLearningCSV.zip (~230 MB)](http://205.174.165.80/CICDataset/CIC-IDS-2017/Dataset/MachineLearningCSV.zip)**
- 🌐 **[Official University of New Brunswick (UNB) Dataset Portal](https://www.unb.ca/cic/datasets/ids-2017.html)**
- 📊 **[Kaggle Dataset Mirror (CSV format)](https://www.kaggle.com/datasets/cicdataset/cicids2017)**

---

## ⚡ 1-Click Automated Download

To automatically download and extract the dataset CSVs directly into this folder, simply run:

```bash
bash data/download_dataset.sh
```

Or manually via terminal:

```bash
cd data/
curl -O http://205.174.165.80/CICDataset/CIC-IDS-2017/Dataset/MachineLearningCSV.zip
unzip MachineLearningCSV.zip
```

---

> [!NOTE]
> The pre-trained model binary (`models/ahhs_model.bin`, 592 bytes) and 240 bit-exact verification vectors (`models/golden_tier3.json`) are already bundled in the repository. You **do not need** to download the raw dataset to build, run, or verify AHHS-IDS.
> Downloading this dataset is only required if you want to train the models from scratch.

---

## 📊 Relevant CSV Files Used by AHHS-IDS

Once unzipped, the key day captures utilized by the training and evaluation pipelines are:

| File Name | Traffic Type | Role in Pipeline |
| :--- | :--- | :--- |
| `Monday-WorkingHours.pcap_ISCX.csv` | Normal user activity | Baseline benign distribution calibration |
| `Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv` | PortScan & probing | Probing & reconnaissance attack evaluation |
| `Wednesday-workingHours.pcap_ISCX.csv` | DoS Slowloris & GoldenEye | Low-and-slow application-layer attack evaluation |

---

## 🔄 Retraining

Once the CSV files are extracted into `data/`, you can train the Tier 1 static inline decision tree:

```bash
make bpf/tier1_tree.h
# or directly:
python3 scripts/train_tier1.py
```
