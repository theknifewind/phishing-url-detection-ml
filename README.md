# 🛡️ Phishing URL Detection System

A **machine learning–based phishing URL detection system** that classifies URLs as **PHISHING** or **LEGITIMATE** using only **URL-based features** — no webpage fetching, no external APIs.

The system is designed with a **security-first approach**, making fast, offline predictions using interpretable machine learning.

---

## 🚀 Key Highlights

- 🔍 URL-only phishing detection  
- ⚡ Fast, offline predictions  
- 🌲 Random Forest classifier with Logistic Regression baseline  
- 🧠 19 interpretable URL features  
- 📊 99.18% accuracy on benchmark dataset  
- 💻 Command-line tool with explainable predictions  
- 🔎 Shows reasons for phishing detection  

---

## 📊 Model Performance

### Random Forest (Main Model)
```
Accuracy:  99.18%
Precision: 99.81%
Recall:    98.28%
F1-Score:  99.04%
ROC-AUC:   99.74%
```

### Logistic Regression (Baseline)
```
Accuracy:  98.95%
Precision: 99.47%
Recall:    98.06%
F1-Score:  98.76%
ROC-AUC:   99.53%
```

> 📈 Random Forest outperforms the baseline by **0.23%** in accuracy with better recall for phishing detection (98.28% vs 98.06%).

> ⚠️ **Note**: Metrics are dataset-based. In real-world usage, **rare false positives may occur**, especially for unusual or legacy URLs. This is an intentional tradeoff to prioritize phishing detection.

---

## 🧠 How It Works

### Feature Engineering (19 Features)

The model uses **19 URL-based features** from the PhiUSIIL dataset that analyze **lexical and structural properties** of URLs, including:

- URL length, domain length, subdomains
- HTTPS usage and suspicious TLDs
- Digits, special characters, hyphens
- IP-based domains and redirect patterns
- Brand name and phishing keyword heuristics

No webpage content is fetched — all features are extracted purely from the URL string.

---

### Machine Learning Models

#### Random Forest Classifier (Main Model)
- **Algorithm**: Random Forest Classifier  
- **Trees**: 100  
- **Max Depth**: 10  
- **Class Weight**: Balanced  
- **Training Data**: ~235,000 URLs (~188,636 training samples)
- **Test Data**: 47,159 URLs

Random Forest was chosen for its robustness, interpretability, and strong performance on tabular data.

#### Logistic Regression (Baseline)
- **Algorithm**: Logistic Regression with StandardScaler
- **Solver**: LBFGS
- **Max Iterations**: 1000
- **Class Weight**: Balanced

The baseline model demonstrates that while simpler models perform well (98.95% accuracy), Random Forest provides incremental improvements in both precision and recall.

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
│   ├── training.ipynb
│   ├── features.py
│   └── predict_url.py
│
├── requirements.txt
└── README.md
```

---

## ⚙️ Setup & Installation
```bash
git clone https://github.com/theknifewind/phishing-url-detection.git
cd phishing-url-detection
pip install -r requirements.txt
```

Place the dataset at:
```
data/raw/PhiUSIIL_Phishing_URL_Dataset.csv
```

**Dataset Source**: [PhiUSIIL Phishing URL Dataset on Kaggle](https://www.kaggle.com/datasets/prishasawhney/phiusiil-phishing-url-dataset)

---

## 🏋️ Train the Model
```bash
cd src
jupyter notebook phishing_detection_training.ipynb
```

Running the notebook will:

* Load and preprocess the dataset (235,795 URLs)
* Extract 19 URL-based features
* Train Logistic Regression baseline model
* Train Random Forest classifier
* Compare model performance side-by-side
* Visualize confusion matrices and ROC curves
* Evaluate on 20% held-out test set (47,159 URLs)
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
Enter URL: https://www.google.com
  [OK] LEGITIMATE (Risk: 3.76%)
     Risk Level: SAFE
     Confidence: 96.24%

Enter URL: http://paypal-verify.xyz/secure/login
  [!] PHISHING (Risk: 99.87%)
     Risk Level: CRITICAL
     Confidence: 99.87%

     Suspicious Indicators:
       1. Uses suspicious TLD (.xyz, .tk, .ml, etc.)
       2. Not using HTTPS (insecure connection)
       3. High similarity to phishing keywords (68.3%)
       4. Multiple hyphens in domain (1)
       5. Deep path structure (2 levels)
```

### Debug Mode (Show All Features)
```bash
python predict_url.py -i
# Then enter: https://www.example.com --debug
```

This will display all feature values used by the model for transparency.

---

### Python API
```python
from predict_url import load_model, predict_url

model = load_model()
result = predict_url(model, "https://www.google.com")

print(result["prediction"])  # "LEGITIMATE" or "PHISHING"
print(result["risk_score"])  # 0.0376
print(result["reasons"])     # List of suspicious indicators (if any)
```

---

## ⚠️ Known Limitations

### Path-Based False Positives
The model may occasionally flag legitimate URLs with long paths (e.g., `github.com/user/repository`) as phishing. This occurs because:
- Phishing URLs often use long, complex paths to obscure malicious intent
- The training dataset may underrepresent legitimate URLs with deep path structures
- The model prioritizes security (minimizing false negatives) over convenience

### False Positives on Some Legitimate Sites
In rare cases, well-known legitimate sites may be flagged due to:
- Complex patterns learned from training data that don't always generalize
- Structural similarities with phishing URLs in the training set
- Class imbalance for certain URL patterns


## 🎯 Features & Capabilities

✅ **Explainable Predictions**: Shows specific reasons why a URL is flagged as phishing  
✅ **No External Dependencies**: Works completely offline  
✅ **Fast Inference**: Predictions in milliseconds  
✅ **Baseline Comparison**: Includes Logistic Regression for performance validation  
✅ **Interactive CLI**: User-friendly command-line interface  
✅ **Debug Mode**: Inspect all feature values for transparency  
✅ **High Precision**: 99.81% precision minimizes false positives  
✅ **Strong Recall**: 98.28% recall catches most phishing attempts  

---

## 🔬 Technical Details

### Feature Categories

The 19 features from the PhiUSIIL dataset are grouped into:

1. **Lexical Features**: URL length, domain length, character patterns
2. **Structural Features**: Subdomains, path depth, TLD analysis
3. **Security Features**: HTTPS usage, IP addresses, suspicious patterns
4. **Heuristic Features**: Brand names, phishing keywords, special characters

### Model Comparison

| Metric | Logistic Regression | Random Forest | Improvement |
|--------|-------------------|---------------|-------------|
| Accuracy | 98.95% | 99.18% | +0.23% |
| Precision | 99.47% | 99.81% | +0.34% |
| Recall | 98.06% | 98.28% | +0.22% |
| F1-Score | 98.76% | 99.04% | +0.28% |
| ROC-AUC | 99.53% | 99.74% | +0.21% |

### Model Selection Rationale

Random Forest was chosen over Logistic Regression because:
- **Better Precision**: 99.81% vs 99.47% (fewer false positives)
- **Better Recall**: 98.28% vs 98.06% (catches more phishing)
- **Robustness**: Handles non-linear patterns and feature interactions
- **Interpretability**: Feature importance analysis available
- **No Scaling Required**: Works with raw features

While both models achieve excellent performance (>98%), Random Forest's incremental improvements justify the additional complexity for a security-critical application.

---

## 🚀 My Contributions

While the feature set comes from the PhiUSIIL dataset, this project includes:

- ✅ Complete implementation of feature extraction pipeline
- ✅ Baseline model comparison (Logistic Regression vs Random Forest)
- ✅ Explainable AI layer showing reasons for predictions
- ✅ Interactive command-line interface with debug mode
- ✅ Production-ready prediction API
- ✅ Comprehensive evaluation and model comparison
- ✅ Documentation of limitations and production considerations

---

## ⭐ Acknowledgments

* [PhiUSIIL Phishing URL Dataset](https://www.kaggle.com/datasets/prishasawhney/phiusiil-phishing-url-dataset) - Original dataset and feature definitions
* scikit-learn, pandas, numpy, matplotlib, seaborn
* tldextract for robust TLD parsing

