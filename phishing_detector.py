import spacy
import re
import json
from typing import Dict, List, Tuple
from pathlib import Path

class PhishingDetector:
    def __init__(self, config_path: str = "config.yml"):
        """Initialize the phishing detector with spaCy model and configuration."""
        try:
            self.nlp = spacy.load("en_core_web_sm", disable=["parser"])  # Disable unused components
            self.config = self._load_config(config_path)
            self.suspicious_patterns = self.config.get("suspicious_patterns", {})
            self.scoring_rules = self.config.get("scoring_rules", {})
        except Exception as e:
            raise RuntimeError(f"Initialization failed: {str(e)}")

        def _load_config(self, path: str) -> Dict:
            """Load configuration from JSON file."""
            try:
                with Path(path).open('r', encoding='utf-8') as f:
                    config = json.load(f)
                    if not config:
                        raise ValueError("Empty or invalid config file")
                    return config
            except FileNotFoundError:
                raise FileNotFoundError(f"Config file not found at {path}")
            except json.JSONDecodeError as e:
                raise ValueError(f"Invalid JSON format: {str(e)}")


    def analyze_email(self, email_text: str) -> Tuple[int, List[str]]:
        """Analyze email for phishing indicators."""
        if not isinstance(email_text, str) or not email_text.strip():
            raise ValueError("Invalid or empty email text")

        score = 0
        flags = []

        # Regex-based pattern matching
        for label, pattern in self.suspicious_patterns.items():
            try:
                matches = re.findall(pattern, email_text, re.IGNORECASE)
                if matches:
                    score += self.scoring_rules.get(label, 0)
                    flags.append(f"{label} found: {', '.join(map(str, matches))}")
            except re.error as e:
                flags.append(f"Invalid regex pattern for {label}: {str(e)}")

        # SpaCy NER for organization detection
        doc = self.nlp(email_text)
        orgs = [ent.text for ent in doc.ents if ent.label_ == "ORG"]
        if not orgs:
            score += self.scoring_rules.get("missing_organization", 0)
            flags.append("No organization detected")

        return score, flags

    def print_results(self, score: int, flags: List[str]) -> None:
        """Print analysis results with verdict."""
        print("=== PHISHING DETECTION RESULTS ===")
        print(f"Email Analysis Score: {score}")
        print("Flags:")
        for flag in flags or ["None"]:
            print(f"- {flag}")

        if score >= 7:
            print("🛑 Likely phishing attempt.")
        elif 4 <= score < 7:
            print("⚠️ Suspicious email — exercise caution.")
        else:
            print("✅ Email appears safe.")

def main():
    """Example usage of PhishingDetector."""
    sample_email = """Subject: Urgent Action Required

    Dear User,

    We have detected unusual activity in your account.
    Please verify your identity within 24 hours by clicking the link below:
    http://fakebank-login.com/verify

    If you do not act now, your account may be permanently disabled.

    Sincerely,
    The Security Team"""

    try:
        detector = PhishingDetector()
        score, flags = detector.analyze_email(sample_email)
        detector.print_results(score, flags)
    except Exception as e:
        print(f"Error: {str(e)}")

if __name__ == "__main__":
    main()