from dataclasses import dataclass
from enum import Enum
import json
from typing import Any, Dict, List, Iterable, Optional, Set
from pathlib import Path

DEFAULT_DB_PATH = Path(__file__).parent / "api_blacklist.json"

class APISeverity (str, Enum):
    # Risk levels for Windows API
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"

@dataclass(frozen = True)
class APIThreatInfo:
    # Analyze info of Windows API call in a thread
    name: str
    category: str
    severity: APISeverity
    description: str
    mitre_technique: Optional[str]

def load_blacklist_database(db_path: Optional[Path | str] = None) -> Dict[str, APIThreatInfo]:
    path = Path(db_path) if db_path else DEFAULT_DB_PATH
    if not path.is_file():
        raise FileNotFoundError(f"Blacklist database file not found: {path}")

    try:
        with open(path, "r", encoding="utf-8") as f:
            raw_data: Dict[str, Dict[str, Any]] = json.load(f)

        db: Dict[str, APIThreatInfo] = {}
        for api_name, info in raw_data.items():
            severity_str = info.get("severity", "MEDIUM").upper()
            try:
                severity = APISeverity(severity_str)
            except ValueError:
                severity = APISeverity.MEDIUM

            db[api_name] = APIThreatInfo(
                name=api_name,
                category=info.get("category", "General"),
                severity=severity,
                description=info.get("description", ""),
                mitre_technique=info.get("mitre_technique")
            )
        return db
    except json.JSONDecodeError as e:
        raise ValueError(f"Error decoding JSON from blacklist database: {e}")

# Merge API name into a Set
API_DATABASE: Dict[str, APIThreatInfo] = load_blacklist_database()
DANGEROUS_APIS_SET: Set[str] = set(API_DATABASE.keys())

def is_blacklised_api(api_name: str) -> bool:
    return api_name in DANGEROUS_APIS_SET

def get_api_threat_info(api_name: str) -> Optional[APIThreatInfo]:
    return API_DATABASE.get(api_name, None)

def inspect_api(api_list: Iterable[str]) -> List[APIThreatInfo]:
    # Inspect a list of API names and return their threat info if they are blacklisted
    found_threats: List[APIThreatInfo] = []
    seen: Set[str] = set()

    for api in api_list:
        if api in DANGEROUS_APIS_SET and api not in seen:
            seen.add(api)
            info = get_api_threat_info(api)
            if info:
                found_threats.append(info)

    severity_order = {
        APISeverity.CRITICAL: 0,
        APISeverity.HIGH: 1,
        APISeverity.MEDIUM: 2,
        APISeverity.LOW: 3
    }

    found_threats.sort(key=lambda x: severity_order[x.severity])
    return found_threats

def summarize_api_risks (api_list: Iterable[str]) -> Dict[str, Any]:
    # summarize the risk levels of a list of API names
    threats = inspect_api(api_list)
    by_category: Dict[str, List[APIThreatInfo]] = {}
    severity_counts = {sev.value: 0 for sev in APISeverity}

    for t in threats:
        by_category.setdefault(t.category, []).append(t.name)
        severity_counts[t.severity.value] += 1

    score = (
        severity_counts["CRITICAL"] * 30 +
        severity_counts["HIGH"] * 15 +
        severity_counts["MEDIUM"] * 5 +
        severity_counts["LOW"] * 1
    )
    score = min(100, score)

    return {
        "total_blacklisted_apis": len(threats),
        "risk_score": score,
        "risk_level": "CRITICAL" if score >= 60 else "HIGH" if score >= 35 else "MEDIUM" if score >= 15 else "LOW",
        "severity_counts": severity_counts,
        "categories": by_category,
        "threat_details": threats
    }