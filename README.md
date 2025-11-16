# 🌐 **AI-Based Security Log Threat Detection & Monitoring System**

*A fusion of deep learning, graph intelligence, and log analytics.*

---

## 🔥 **Overview**

This project is a full-stack security analytics system designed to **ingest, parse, learn from, and detect threats** inside network and system logs.
It brings together the calm logic of statistics, the pattern-seeking mind of LSTM networks, and the structural awareness of Graph Convolutional Networks (GCN).

The goal is simple:
**See danger before it speaks. Detect anomalies before they grow teeth.**

---

## 🚀 **Core Features**

### **1️⃣ Log Ingestion Engine**

* Supports raw log formats:

  * Apache Access Logs
  * OpenSSH Authentication Logs
* Reads, normalizes, and structures logs into clean dataframes.
* Handles different timestamps, event formats, and network fields.

### **2️⃣ Dataset Support**

* **UNSW-NB15** (structured flow-based attacks)
* **CICIDS 2017** (realistic network intrusion scenarios)
* Raw system + application logs (Apache, SSH)

These datasets build a rich training set combining academic rigor and real-world chaos.

### **3️⃣ Preprocessing Pipeline**

* Cleans, encodes, normalizes network flows.
* Builds timestamp-aligned sequences for LSTM.
* Constructs graph structures (IP ↔ IP, user ↔ host, event relations) for GCN.

### **4️⃣ Deep Learning Models**

#### **LSTM Threat Detection**

Captures sequential patterns in network flows:

* DoS/DDoS behavior
* scanning footprints
* anomalous login sequences

#### **GCN Graph-Based Detection**

Models relationships like:

* source ↔ destination communication
* user ↔ authentication attempts
* event correlations

Perfect for spotting suspicious link patterns.

### **5️⃣ Anomaly Detection Layer**

* Frequency-based anomalies
* Sequence breaks
* Suspicious IP behavior
* Abnormal request patterns
* Failed SSH attempts clustering

### **6️⃣ Real-Time Monitoring Dashboard**

A small dashboard (Streamlit) offering:

* live log summaries
* detected anomalies
* traffic heatmaps
* model predictions

---

## 📁 **Repository Structure**

```
security-log-threat-detection/
│
├── data/
│   ├── raw_logs/       # Datasets stored locally (ignored by Git)
│   └── processed/
│
├── notebooks/
│   ├── EDA.ipynb
│   ├── LSTM_model.ipynb
│   └── GCN_model.ipynb
│
├── src/
│   ├── ingest/
│   │   └── log_reader.py
│   ├── preprocess/
│   │   └── clean_transform.py
│   ├── models/
│   │   ├── lstm_model.py
│   │   └── gcn_model.py
│   ├── detection/
│   │   └── anomaly_detector.py
│   └── api/
│       └── inference_api.py
│
├── dashboard/
│   └── app.py
│
├── requirements.txt
├── README.md
└── .gitignore
```

---

## ⚙️ **Setup Instructions**

### **1. Clone the repository**

```bash
git clone https://github.com/<your-username>/security-log-threat-detection.git
cd security-log-threat-detection
```

### **2. Create virtual environment**

```bash
python -m venv venv
venv\Scripts\activate
```

### **3. Install dependencies**

```bash
pip install -r requirements.txt
```

### **4. Start Jupyter notebook**

```bash
jupyter lab
```

---

## 📊 **Datasets (stored locally only)**

This project uses:

* **UNSW-NB15**
* **CICIDS 2017 (MachineLearningCSVs)**
* **Apache 2k raw log dataset**
* **OpenSSH raw log dataset**

These datasets are **large** and stored only in `data/raw_logs/`
They are ignored via `.gitignore` and not pushed to GitHub.

---

## 🔍 **Progress Roadmap**

### **✔ Phase 1: Setup & Data Collection**

Download datasets, structure repo, prepare raw logs.

### **🔜 Phase 2 (Nov 17–18): EDA & Understanding the Data**

* Explore UNSW & CICIDS
* Parse Apache/SSH logs
* Identify sequences & graph relationships

### **🔜 Phase 3: Preprocessing Pipelines**

Build LSTM & GCN data prep systems.

### **🔜 Phase 4: Model Training + Evaluation**

### **🔜 Phase 5: Dashboard + API Integration**

---

## 💡 **Technologies Used**

* **Python**
* **PyTorch** / **PyTorch Geometric (GCN)**
* **pandas, numpy, scikit-learn**
* **Matplotlib / Seaborn**
* **Streamlit** (dashboard)
* **JupyterLab**

---

## 🎤 **Author**

**Shashank** – Engineering at PES University
Driven to build systems that see patterns hidden in the storm.

---