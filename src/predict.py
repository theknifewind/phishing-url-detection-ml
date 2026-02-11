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

        return {
            "url": url,
            "prediction": prediction,
            "risk_score": round(risk_score, 4),
            "risk_level": risk_level,
            "confidence": round(max(risk_score, 1 - risk_score), 4),
        }
    except Exception as e:
        raise RuntimeError(f"Failed to predict URL '{url}': {e}")


def interactive_mode(model_bundle: dict):
    """Interactive loop for manual URL entry."""
    print("\n" + "=" * 60)
    print("  PHISHING URL DETECTOR - Manual URL Entry")
    print("=" * 60)
    print("  Enter URLs to check. Type 'quit' or 'q' to exit.")
    print("=" * 60 + "\n")

    while True:
        try:
            url = input("Enter URL: ").strip()
        except (EOFError, KeyboardInterrupt):
            print("\nExiting.")
            break

        if not url:
            continue
        if url.lower() in ("quit", "q", "exit"):
            print("Exiting.")
            break

        try:
            result = predict_url(model_bundle, url)
            _print_result(result)
        except Exception as e:
            print(f"  Error: {e}\n")


def _print_result(result: dict):
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
    print(f"     Confidence: {result['confidence']:.2%}\n")


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
            _print_result(result)
        except Exception as e:
            print(f"Error for {url}: {e}", file=sys.stderr)


if __name__ == "__main__":
    main()