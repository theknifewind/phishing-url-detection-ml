# Phishing Website Risk Detection using Machine Learning

## 📌 Project Overview
This project implements a **Machine Learning–based phishing website detection system** that predicts the **risk level of a website** using **URL and domain-level features**.  
Instead of only giving a binary output (phishing / legitimate), the system produces a **probability-based phishing risk score**, making it more suitable for real-world security applications.

---

## 🎯 Objectives
- Detect phishing websites using machine learning
- Compare a baseline model with a stronger ensemble model
- Generate **risk scores** instead of only binary predictions
- Build an **explainable and reproducible ML pipeline**

---

## 🧠 Machine Learning Approach

### Problem Type
- **Supervised Binary Classification**
- Target variable:
  - `0` → Legitimate website
  - `1` → Phishing website

### Dataset
- URL and domain-based dataset with **pre-extracted features**
- Total features: **111**
- Feature types include:
  - URL length and structure
  - Directory depth
  - Domain age and expiration
  - DNS and hosting characteristics
- Feature extraction was already performed in the dataset; this project focuses on **modeling and evaluation**.

---

## 🔍 Exploratory Data Analysis (EDA)
- Checked dataset shape and structure
- Verified absence of missing values
- Identified and removed duplicate rows
- Analyzed class distribution to handle imbalance
- Confirmed dataset suitability for supervised learning

---

## 🏗️ Model Pipeline

### 1️⃣ Baseline Model: Logistic Regression
- Used as a **baseline classifier**
- Helped validate dataset quality and pipeline correctness
- Achieved high phishing recall but lower precision due to linear limitations

### 2️⃣ Final Model: Random Forest Classifier
- Handles non-linear feature interactions
- Works well with high-dimensional tabular data
- Does not require feature scaling
- Provides feature importance for explainability

#### Final Performance (Large Dataset)
- **Accuracy:** ~97%
- **High precision and recall for both phishing and legitimate classes**
- Significantly outperformed Logistic Regression

---

## ⚠️ Risk Scoring System
Instead of only predicting classes, the model outputs a **phishing probability score** using:

```python
predict_proba()
