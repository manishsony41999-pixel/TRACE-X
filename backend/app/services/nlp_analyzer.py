"""
TRACE-X Machine Learning & NLP Phishing Content Analyzer
Extracts semantic intent, urgency indicators, credential harvesting language,
financial lures, and statistical lexical features from email subject and body.
Computes explainable phishing probability and keyword triggers.
"""

import re
import math
from typing import Dict, Any, List, Optional


# Semantic Intent Rulebook with weights
INTENT_PATTERNS = {
    "urgency_coercion": [
        (r"\b(?:immediate(?:ly)?|urgent(?:ly)?|critical(?:ly)?)\b", 2.0, "High urgency keyword"),
        (r"\b(?:account (?:will be |is )?suspended|account terminated|access denied|permanently deleted)\b", 3.0, "Threat of account suspension or termination"),
        (r"\b(?:within (?:24|48|12|1|2) hours?|immediately|right now|before it'?s too late|last chance)\b", 2.5, "Strict deadline constraint"),
        (r"\b(?:action required|unauthorized (?:login|activity|access)|unusual activity)\b", 2.5, "Alarmist action prompt"),
        (r"\b(?:final (?:warning|notice)|failure to (?:comply|respond))\b", 3.0, "Ultimatum / coercion pattern")
    ],
    "credential_harvesting": [
        (r"\b(?:verify (?:your )?(?:account|identity|information|email|wallet|credentials))\b", 3.0, "Identity/Account verification prompt"),
        (r"\b(?:update (?:your )?(?:password|billing|payment|security|profile))\b", 2.5, "Password or billing update request"),
        (r"\b(?:click (?:here|the link below|this button) to (?:log ?in|sign ?in|verify|unlock))\b", 3.5, "Direct credential harvesting call-to-action"),
        (r"\b(?:confirm your (?:password|pin|social security|card|account))\b", 3.5, "Sensitive credential confirmation request"),
        (r"\b(?:re-?activate (?:your )?(?:account|mailbox|service))\b", 2.5, "Account reactivation lure")
    ],
    "financial_lure": [
        (r"\b(?:wire transfer|direct deposit|bank transfer|swift transfer)\b", 2.5, "Bank or wire transfer solicitation"),
        (r"\b(?:bitcoin|btc|cryptocurrency|crypto wallet|ethereum|usdt)\b", 2.5, "Cryptocurrency payment reference"),
        (r"\b(?:gift card|itunes card|google play card|steam card)\b", 3.0, "Gift card payout request"),
        (r"\b(?:overdue invoice|unpaid invoice|payment due|remittance advice|invoice attached)\b", 2.0, "Fake invoice/payment lure"),
        (r"\b(?:you have won|lottery prize|inheritance|million (?:dollars|usd|gbp|eur))\b", 3.5, "Lottery / Advance fee fraud pattern")
    ],
    "authority_impersonation": [
        (r"\b(?:it (?:help ?desk|support|department|admin)|security team|system administrator)\b", 2.0, "IT / Security team impersonation"),
        (r"\b(?:payroll (?:department|team)|human resources|hr department)\b", 2.0, "HR / Payroll impersonation"),
        (r"\b(?:chief executive officer|ceo|cfo|executive director|board of directors)\b", 2.5, "Executive authority impersonation"),
        (r"\b(?:microsoft (?:security|support|team)|google (?:security|team)|apple support|paypal support)\b", 2.5, "Tech brand authority lure")
    ],
    "generic_salutation": [
        (r"\b(?:dear (?:customer|user|client|valued customer|member|friend|account holder|sir/madam))\b", 1.5, "Impersonal/generic greeting")
    ]
}


def analyze_nlp_content(
    subject: Optional[str] = "",
    body_text: Optional[str] = "",
    html_content: Optional[str] = ""
) -> Dict[str, Any]:
    """
    Analyzes email text content using natural language processing heuristics,
    intent classification, and statistical probability modeling.
    """
    subject_str = subject or ""
    body_str = body_text or ""
    full_text = f"{subject_str}\n{body_str}".strip()

    if not full_text:
        return {
            "phishing_probability": 0.0,
            "risk_tier": "LOW",
            "intents_detected": [],
            "matched_keywords": [],
            "lexical_features": {
                "caps_ratio": 0.0,
                "exclamation_count": 0,
                "word_count": 0,
                "urgency_score": 0.0,
                "credential_score": 0.0
            },
            "summary": "No text content available for NLP analysis."
        }

    # 1. Lexical and Surface Features
    words = re.findall(r"\b\w+\b", full_text)
    word_count = len(words)
    uppercase_words = [w for w in words if w.isupper() and len(w) > 1]
    caps_ratio = round(len(uppercase_words) / max(word_count, 1), 3)
    exclamation_count = full_text.count("!")
    question_count = full_text.count("?")

    # 2. Semantic Intent & Keyword Extraction
    total_intent_score = 0.0
    matched_keywords: List[Dict[str, Any]] = []
    category_scores: Dict[str, float] = {
        "urgency_coercion": 0.0,
        "credential_harvesting": 0.0,
        "financial_lure": 0.0,
        "authority_impersonation": 0.0,
        "generic_salutation": 0.0
    }

    lower_text = full_text.lower()

    for category, pattern_list in INTENT_PATTERNS.items():
        for regex_pattern, weight, description in pattern_list:
            matches = list(re.finditer(regex_pattern, lower_text, re.IGNORECASE))
            if matches:
                category_scores[category] += weight * len(matches)
                total_intent_score += weight * len(matches)
                for m in matches:
                    matched_phrase = full_text[m.start():m.end()]
                    start_snippet = max(0, m.start() - 25)
                    end_snippet = min(len(full_text), m.end() + 25)
                    context_snippet = full_text[start_snippet:end_snippet].replace("\n", " ").strip()

                    matched_keywords.append({
                        "category": category,
                        "phrase": matched_phrase,
                        "description": description,
                        "weight": weight,
                        "context": f"...{context_snippet}..."
                    })

    # Add Caps and Exclamation Penalties
    if caps_ratio > 0.25:
        total_intent_score += 2.0
    if exclamation_count >= 3:
        total_intent_score += 1.5

    # 3. Machine Learning Probability Model (Logistic Sigmoid Function)
    logit_z = -3.0 + (total_intent_score * 0.85) + (caps_ratio * 3.0) + (min(exclamation_count, 5) * 0.3)
    phishing_prob = round(1.0 / (1.0 + math.exp(-logit_z)), 3)

    # 4. Risk Tier Mapping
    if phishing_prob >= 0.75:
        risk_tier = "CRITICAL"
    elif phishing_prob >= 0.50:
        risk_tier = "HIGH"
    elif phishing_prob >= 0.25:
        risk_tier = "MEDIUM"
    else:
        risk_tier = "LOW"

    # 5. Detected Intent Categories
    intents_detected = [cat for cat, score in category_scores.items() if score > 0]

    # 6. Human-Readable Explanation Summary
    if not intents_detected:
        summary = "Natural language analysis found normal conversational tone with no detectable urgency or credential lures."
    else:
        summary_parts = []
        if category_scores["credential_harvesting"] > 0:
            summary_parts.append("credential harvesting prompts")
        if category_scores["urgency_coercion"] > 0:
            summary_parts.append("high-urgency coercive language")
        if category_scores["authority_impersonation"] > 0:
            summary_parts.append("authority/brand impersonation")
        if category_scores["financial_lure"] > 0:
            summary_parts.append("financial solicitation lures")
        if category_scores["generic_salutation"] > 0:
            summary_parts.append("impersonal generic greetings")
        
        summary = f"Content exhibits strong phishing indicators: {', '.join(summary_parts)} with a {int(phishing_prob * 100)}% NLP threat probability."

    return {
        "phishing_probability": phishing_prob,
        "risk_tier": risk_tier,
        "intents_detected": intents_detected,
        "matched_keywords": matched_keywords[:15],
        "category_scores": category_scores,
        "lexical_features": {
            "word_count": word_count,
            "caps_ratio": caps_ratio,
            "exclamation_count": exclamation_count,
            "question_count": question_count,
            "urgency_score": category_scores["urgency_coercion"],
            "credential_score": category_scores["credential_harvesting"]
        },
        "summary": summary
    }
