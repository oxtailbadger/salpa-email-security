from datetime import datetime, timezone


def build_report(results: list[dict]) -> dict:
    report_results = []
    for r in results:
        parsed = r["parsed"]
        features = r["features"]
        report_results.append({
            "file": r["file"],
            "subject": parsed["subject"],
            "from": parsed["from"],
            "date": parsed["date"],
            "phishing_score": features["phishing_score"],
            "verdict": features["verdict"],
            "features": features["features"],
        })

    return {
        "report_generated": datetime.now(timezone.utc).isoformat(),
        "files_analyzed": len(report_results),
        "results": report_results,
    }
