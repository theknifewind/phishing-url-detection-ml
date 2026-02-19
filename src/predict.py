#!/usr/bin/env python3
"""
Phishing URL Predictor - Manual URL Entry with Risk Scores
Run this script to interactively predict phishing risk for URLs you enter.
"""
import sys
from pathlib import Path

import joblib
import pandas as pd

from features import extract_features

# Default model path - model is in project root /models, script is in /src
DEFAULT_MODEL_PATH = Path(__file__).parent.parent / "models" / "url_rf_model.pkl"


def load_model(model_path: Path = None):
    """Load the trained model bundle."""
    path = model_path or DEFAULT_MODEL_PATH
    if not path.exists():
        raise FileNotFoundError(
            f"Model not found at {path}. Run the training notebook first."
        )
    try:
        model_bundle = joblib.load(path)
        # Validate model bundle structure
        if not isinstance(model_bundle, dict) or "model" not in model_bundle or "features" not in model_bundle:
            raise ValueError("Invalid model bundle format. Expected dict with 'model' and 'features' keys.")
        return model_bundle
    except Exception as e:
        raise RuntimeError(f"Failed to load model: {e}")


def analyze_features(features: dict, feature_importance: dict) -> list:
    """
    Analyze which features contribute most to phishing detection.
    Returns list of suspicious features with explanations.
    """
    reasons = []
    
    # Define thresholds and explanations for suspicious features
    feature_checks = {
        "IsDomainIP": {
            "threshold": 1,
            "operator": "==",
            "reason": "Domain is an IP address (common in phishing)"
        },
        "URLLength": {
            "threshold": 75,
            "operator": ">",
            "reason": f"Unusually long URL ({features.get('URLLength', 0)} characters)"
        },
        "SuspiciousTLD": {
            "threshold": 1,
            "operator": "==",
            "reason": "Uses suspicious TLD (.xyz, .tk, .ml, etc.)"
        },
        "HasHTTPS": {
            "threshold": 0,
            "operator": "==",
            "reason": "Not using HTTPS (insecure connection)"
        },
        "TrustedBrandOnHTTP": {
            "threshold": 1,
            "operator": "==",
            "reason": "Brand name in subdomain without HTTPS"
        },
        "SubdomainLevel": {
            "threshold": 2,
            "operator": ">=",
            "reason": f"Multiple subdomains ({features.get('SubdomainLevel', 0)} levels)"
        },
        "HasAtSymbol": {
            "threshold": 1,
            "operator": "==",
            "reason": "Contains @ symbol (URL obfuscation technique)"
        },
        "DoubleSlashRedirecting": {
            "threshold": 1,
            "operator": "==",
            "reason": "Multiple // in URL (redirect obfuscation)"
        },
        "URLSimilarityIndex": {
            "threshold": 40,
            "operator": ">",
            "reason": f"High similarity to phishing keywords ({features.get('URLSimilarityIndex', 0):.1f}%)"
        },
        "PathDepth": {
            "threshold": 4,
            "operator": ">",
            "reason": f"Deep path structure ({features.get('PathDepth', 0)} levels)"
        },
        "DigitCount": {
            "threshold": 8,
            "operator": ">",
            "reason": f"Many digits in URL ({features.get('DigitCount', 0)})"
        },
        "SpecialCharCount": {
            "threshold": 6,
            "operator": ">",
            "reason": f"Many special characters ({features.get('SpecialCharCount', 0)})"
        },
        "HyphenCount": {
            "threshold": 3,
            "operator": ">",
            "reason": f"Multiple hyphens in domain ({features.get('HyphenCount', 0)})"
        },
        "TLDLegitimateProb": {
            "threshold": 0.5,
            "operator": "<",
            "reason": f"Low trust TLD (legitimacy: {features.get('TLDLegitimateProb', 0):.2f})"
        },
        "CharContinuationRate": {
            "threshold": 0.15,
            "operator": ">",
            "reason": "High character repetition rate"
        }
    }
    
    # Check each feature
    for feature_name, check in feature_checks.items():
        if feature_name not in features:
            continue
            
        value = features[feature_name]
        threshold = check["threshold"]
        operator = check["operator"]
        
        is_suspicious = False
        if operator == "==":
            is_suspicious = (value == threshold)
        elif operator == ">":
            is_suspicious = (value > threshold)
        elif operator == ">=":
            is_suspicious = (value >= threshold)
        elif operator == "<":
            is_suspicious = (value < threshold)
        
        if is_suspicious:
            # Get feature importance if available
            importance = feature_importance.get(feature_name, 0)
            reasons.append({
                "feature": feature_name,
                "reason": check["reason"],
                "importance": importance
            })
    
    # Sort by importance (most important first)
    reasons.sort(key=lambda x: x["importance"], reverse=True)
    
    return reasons


def predict_url(model_bundle: dict, url: str) -> dict:
    """
    Predict phishing risk for a single URL.
    Returns: dict with prediction, risk_score, and details
    """
    if not url or not isinstance(url, str):
        raise ValueError("URL must be a non-empty string")
    
    # Add scheme if missing for proper URL parsing
    url = url.strip()
    if not url.startswith(('http://', 'https://')):
        url = 'http://' + url
    
    try:
        features = extract_features(url)
        feature_names = model_bundle["features"]
        X = pd.DataFrame([features])[feature_names]

        model = model_bundle["model"]
        
        # Check if labels were inverted during training
        labels_inverted = model_bundle.get("labels_inverted", True)
        
        if labels_inverted:
            # Labels were inverted: 0=legitimate, 1=phishing
            risk_score = model.predict_proba(X)[0][1]  # P(class 1) = P(phishing)
        else:
            # Labels NOT inverted: 0=phishing, 1=legitimate (backwards)
            risk_score = model.predict_proba(X)[0][0]  # P(class 0) = P(phishing)

        prediction = "PHISHING" if risk_score >= 0.5 else "LEGITIMATE"

        # Risk level interpretation
        if risk_score >= 0.9:
            risk_level = "CRITICAL"
        elif risk_score >= 0.7:
            risk_level = "HIGH"
        elif risk_score >= 0.5:
            risk_level = "MEDIUM"
        elif risk_score >= 0.3:
            risk_level = "LOW"
        else:
            risk_level = "SAFE"

        # Get feature importances from model
        feature_importance_dict = {}
        if hasattr(model, "feature_importances_"):
            importances = model.feature_importances_
            for feature, importance in zip(feature_names, importances):
                feature_importance_dict[feature] = importance
        
        # Analyze features to get reasons
        reasons = analyze_features(features, feature_importance_dict)

        return {
            "url": url,
            "prediction": prediction,
            "risk_score": round(risk_score, 4),
            "risk_level": risk_level,
            "confidence": round(max(risk_score, 1 - risk_score), 4),
            "reasons": reasons,
            "features": features
        }
    except Exception as e:
        raise RuntimeError(f"Failed to predict URL '{url}': {e}")


def interactive_mode(model_bundle: dict):
    """Interactive loop for manual URL entry."""
    print("\n" + "=" * 60)
    print("  PHISHING URL DETECTOR - Manual URL Entry")
    print("=" * 60)
    print("  Enter URLs to check. Type 'quit' or 'q' to exit.")
    print("  Add '--debug' after URL to see all features.")
    print("=" * 60 + "\n")

    while True:
        try:
            url_input = input("Enter URL: ").strip()
        except (EOFError, KeyboardInterrupt):
            print("\nExiting.")
            break

        if not url_input:
            continue
        if url_input.lower() in ("quit", "q", "exit"):
            print("Exiting.")
            break

        # Check for debug flag
        show_debug = False
        if "--debug" in url_input:
            url_input = url_input.replace("--debug", "").strip()
            show_debug = True

        try:
            result = predict_url(model_bundle, url_input)
            _print_result(result, show_all_features=show_debug)
        except Exception as e:
            print(f"  Error: {e}\n")


def _print_result(result: dict, show_all_features: bool = False):
    """Pretty-print prediction result."""
    risk = result["risk_score"]
    level = result["risk_level"]
    pred = result["prediction"]

    # Indicators (ASCII-safe for Windows)
    if pred == "PHISHING":
        icon = "[!]"
        status = f"PHISHING (Risk: {risk:.2%})"
    else:
        icon = "[OK]"
        status = f"LEGITIMATE (Risk: {risk:.2%})"

    print(f"\n  {icon} {status}")
    print(f"     Risk Level: {level}")
    print(f"     Confidence: {result['confidence']:.2%}")
    
    # Display reasons if phishing or high risk
    reasons = result.get("reasons", [])
    
    if pred == "PHISHING":
        if reasons:
            print(f"\n     Suspicious Indicators:")
            # Show top 5 reasons
            for i, reason_info in enumerate(reasons[:5], 1):
                print(f"       {i}. {reason_info['reason']}")
        else:
            print(f"\n     Note: Model prediction based on learned patterns.")
            print(f"     No individual features exceeded thresholds.")
            
        # Show key features in debug mode
        if show_all_features:
            features = result.get("features", {})
            print(f"\n     Key Feature Values:")
            key_features = ["URLLength", "HasHTTPS", "HasBrandName", "TLDLegitimateProb", 
                           "SubdomainLevel", "PathDepth", "SuspiciousTLD", "URLSimilarityIndex",
                           "DigitCount", "SpecialCharCount", "HyphenCount"]
            for feat in key_features:
                if feat in features:
                    print(f"       - {feat}: {features[feat]}")
                    
    elif risk > 0.3:
        if reasons:
            print(f"\n     Suspicious Indicators:")
            for i, reason_info in enumerate(reasons[:5], 1):
                print(f"       {i}. {reason_info['reason']}")
    
    print()


def main():
    import argparse

    parser = argparse.ArgumentParser(description="Phishing URL Predictor with Risk Scores")
    parser.add_argument(
        "urls",
        nargs="*",
        help="URL(s) to predict. If none, run in interactive mode.",
    )
    parser.add_argument(
        "-m", "--model",
        type=Path,
        default=DEFAULT_MODEL_PATH,
        help="Path to model file",
    )
    parser.add_argument(
        "-i", "--interactive",
        action="store_true",
        help="Run in interactive mode for manual URL entry",
    )
    parser.add_argument(
        "--debug",
        action="store_true",
        help="Show all feature values for predictions",
    )
    args = parser.parse_args()

    try:
        model_bundle = load_model(args.model)
    except FileNotFoundError as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        print(f"Error loading model: {e}", file=sys.stderr)
        sys.exit(1)

    if args.interactive or (not args.urls):
        interactive_mode(model_bundle)
        return

    for url in args.urls:
        try:
            result = predict_url(model_bundle, url)
            _print_result(result, show_all_features=args.debug)
        except Exception as e:
            print(f"Error for {url}: {e}", file=sys.stderr)


if __name__ == "__main__":
    main()