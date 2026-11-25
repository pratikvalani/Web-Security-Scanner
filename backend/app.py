import csv
import io
import json
import os
from pathlib import Path
from flask import (
    Flask,
    Response,
    flash,
    redirect,
    render_template,
    request,
    url_for,
)

from backend.database import (
    delete_scan_by_id,
    get_all_scans,
    get_scan_by_id,
    init_db,
    save_scan,
)
from backend.scanner import run_full_assessment

PROJECT_ROOT = Path(__file__).resolve().parent.parent
FRONTEND_DIR = PROJECT_ROOT / "frontend"

app = Flask(
    __name__,
    template_folder=str(FRONTEND_DIR / "templates"),
    static_folder=str(FRONTEND_DIR / "static"),
)
app.secret_key = os.environ.get("FLASK_SECRET_KEY", "dev-secret-change-in-production")

init_db()


@app.route("/", methods=["GET", "POST"])
def index():
    if request.method == "POST":
        target_url = request.form.get("target_url", "").strip()
        if not target_url:
            flash("Please enter a valid target URL or domain.", "error")
            return redirect(url_for("index"))

        try:
            report = run_full_assessment(target_url)
            scan_id = save_scan(
                target_url=report["target_url"],
                domain=report["domain"],
                risk_score=report["risk_score"],
                risk_level=report["risk_level"],
                report_data=report,
            )
            return redirect(url_for("view_report", scan_id=scan_id))
        except Exception as exc:
            flash(f"Scan error: {exc}", "error")
            return redirect(url_for("index"))

    scans = get_all_scans()
    return render_template("index.html", scans=scans)


@app.route("/report/<int:scan_id>")
def view_report(scan_id):
    scan = get_scan_by_id(scan_id)
    if not scan:
        flash("Assessment report not found.", "error")
        return redirect(url_for("index"))
    return render_template("report.html", scan=scan, report=scan["report"])


@app.route("/report/<int:scan_id>/export/json")
def export_report_json(scan_id):
    scan = get_scan_by_id(scan_id)
    if not scan:
        flash("Assessment report not found.", "error")
        return redirect(url_for("index"))

    payload = {
        "scan_id": scan["id"],
        "scan_date": scan["scan_date"],
        "report": scan["report"],
    }
    filename = f"security-report-{scan['domain']}-{scan['id']}.json"
    return Response(
        json.dumps(payload, indent=2),
        mimetype="application/json",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


@app.route("/report/<int:scan_id>/export/csv")
def export_report_csv(scan_id):
    scan = get_scan_by_id(scan_id)
    if not scan:
        flash("Assessment report not found.", "error")
        return redirect(url_for("index"))

    report = scan["report"]
    output = io.StringIO()
    writer = csv.writer(output)

    writer.writerow(["Section", "Item", "Severity", "Details / Remediation"])
    writer.writerow(
        [
            "Summary",
            f"Target: {report['target_url']} ({report['ip_address']})",
            report["risk_level"],
            f"Risk Score: {report['risk_score']}/100 | Scan Date: {scan['scan_date']}",
        ]
    )
    writer.writerow(
        [
            "SSL/TLS",
            f"Protocol: {report['ssl']['protocol']} | Issuer: {report['ssl']['issuer']}",
            report["ssl"]["severity"],
            f"{report['ssl']['message']} | Expires: {report['ssl']['expiry_date']}",
        ]
    )

    for item in report.get("headers", []):
        writer.writerow(
            [
                item.get("category", "HTTP Security Header"),
                item.get("issue", ""),
                item.get("severity", ""),
                item.get("remediation", ""),
            ]
        )

    for port in report.get("ports", []):
        writer.writerow(
            [
                "Open Port",
                f"{port['port']}/TCP ({port['service']})",
                port["severity"],
                port["note"],
            ]
        )

    filename = f"security-report-{scan['domain']}-{scan['id']}.csv"
    return Response(
        output.getvalue(),
        mimetype="text/csv",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


@app.route("/delete/<int:scan_id>", methods=["POST"])
def delete_scan(scan_id):
    if delete_scan_by_id(scan_id):
        flash(f"Scan #{scan_id} removed from history.", "success")
    else:
        flash("Scan record not found.", "error")
    return redirect(url_for("index"))


if __name__ == "__main__":
    app.run(debug=True)