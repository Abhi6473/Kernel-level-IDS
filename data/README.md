# CIC-IDS-2017 Dataset Guide

The AHHS-IDS pipeline is evaluated on the benchmark **CIC-IDS-2017** dataset from the Canadian Institute for Cybersecurity (University of New Brunswick).

> [!NOTE]
> The pre-trained model binary (`models/ahhs_model.bin`, 592 bytes) and 240 bit-exact verification vectors (`models/golden_tier3.json`) are already bundled in the repository. You **do not need** to download the raw dataset to build, run, or verify AHHS-IDS.
> Downloading this dataset is only required if you want to train the models from scratch.

---

## 1. Official Download Links

The dataset can be obtained from any of the following sources:

- **Official UNB Project Page**:
  [https://www.unb.ca/cic/datasets/ids-2017.html](https://www.unb.ca/cic/datasets/ids-2017.html)
- **Direct UNB Archive (MachineLearningCVE / GeneratedLabelledFlows ZIP - ~230 MB compressed)**:
  `http://205.174.165.80/CICDataset/CIC-IDS-2017/Dataset/MachineLearningCSV.zip`
- **Kaggle Mirror (Pre-extracted CSVs)**:
  [https://www.kaggle.com/datasets/cicdataset/cicids2017](https://www.kaggle.com/datasets/cicdataset/cicids2017)

---

## 2. Fast Download via Terminal

You can download and extract the dataset CSVs directly into this folder:

```bash
cd data/

# Download the official preprocessed CSV archive
curl -O http://205.174.165.80/CICDataset/CIC-IDS-2017/Dataset/MachineLearningCSV.zip

# Extract CSV files
unzip MachineLearningCSV.zip
```

---

## 3. Relevant CSV Files Used by AHHS-IDS

Once unzipped, the key day captures utilized by the training and evaluation pipelines are:

| File Name | Traffic Type | Role in Pipeline |
| :--- | :--- | :--- |
| `Monday-WorkingHours.pcap_ISCX.csv` | Normal user activity | Baseline benign distribution calibration |
| `Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv` | PortScan & probing | Probing & reconnaissance attack evaluation |
| `Wednesday-workingHours.pcap_ISCX.csv` | DoS Slowloris & GoldenEye | Low-and-slow application-layer attack evaluation |

---

## 4. Retraining

Once the CSV files are extracted into `data/`, you can train the Tier 1 static inline decision tree:

```bash
make bpf/tier1_tree.h
# or directly:
python3 scripts/train_tier1.py
```
