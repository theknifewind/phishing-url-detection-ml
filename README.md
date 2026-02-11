# 🛡️ Phishing URL Detection System

A **machine learning–based phishing URL detection system** that classifies URLs as **PHISHING** or **LEGITIMATE** using only **URL-based features** — no webpage fetching, no external APIs.

The system is designed with a **security-first approach**, making fast, offline predictions using interpretable machine learning.

---

## 🚀 Key Highlights

- 🔍 URL-only phishing detection  
- ⚡ Fast, offline predictions  
- 🌲 Random Forest classifier  
- 🧠 19 handcrafted, interpretable URL features  
- 📊 ~99% accuracy on benchmark dataset  
- 💻 Command-line tool + Python API  

---

## 📊 Model Performance

```

Accuracy:  99.17%
Precision: 99.80%
Recall:    98.27%
F1-Score:  99.03%
ROC-AUC:   99.73%

```

> ⚠️ Metrics are dataset-based.  
> In real-world usage, **rare false positives may occur**, especially for unusual or legacy URLs.  
> This is an intentional tradeoff to prioritize phishing detection.

---

## 🧠 How It Works

### Feature Engineering (19 Features)

The model analyzes **lexical and structural properties** of URLs, including:

- URL length, domain length, subdomains
- HTTPS usage and suspicious TLDs
- Digits, special characters, hyphens
- IP-based domains and redirect patterns
- Brand name and phishing keyword heuristics

No webpage content is fetched.

---

### Machine Learning Model

- **Algorithm**: Random Forest Classifier  
- **Trees**: 100  
- **Max Depth**: 10  
- **Class Weight**: Balanced  
- **Training Data**: ~235,000 URLs  

Random Forest was chosen for its robustness, interpretability, and strong performance on tabular data.

---

## 📁 Project Structure

```

phishing-url-detection/
│
├── data/
│   └── raw/
│       └── PhiUSIIL_Phishing_URL_Dataset.csv
│
├── models/
│   └── url_rf_model.pkl
│
├── src/
│   ├── phishing_detection_training.ipynb
│   ├── features.py
│   └── predict_url.py
│
├── requirements.txt
└── README.md

````

---

## ⚙️ Setup & Installation

```bash
git clone https://github.com/theknifewind/phishing-url-detection.git
cd phishing-url-detection
pip install -r requirements.txt
````

Place the dataset at:

```
data/raw/PhiUSIIL_Phishing_URL_Dataset.csv
```

---

## 🏋️ Train the Model

```bash
cd src
jupyter notebook phishing_detection_training.ipynb
```

Running the notebook will:

* Extract features
* Train the model
* Evaluate performance
* Save the trained model

---

## 🔮 Predict URLs

### Command Line (Interactive)

```bash
cd src
python predict_url.py -i
```

Example output:

```
[OK] LEGITIMATE (Risk: 3.7%)
[!] PHISHING   (Risk: 99.9%)
```

---

### Python API

```python
from predict_url import load_model, predict_url

model = load_model()
result = predict_url(model, "https://www.google.com")

print(result["prediction"], result["risk_score"])
```

---

## ⚠️ Design Note

This system **prioritizes security over convenience**.

* Some legitimate URLs may resemble phishing patterns
* This reduces the risk of missing real phishing attacks
* In production systems, such models are combined with allowlists and reputation checks

---

## ⭐ Acknowledgments

* PhiUSIIL Phishing URL Dataset
* scikit-learn, pandas, numpy

---

