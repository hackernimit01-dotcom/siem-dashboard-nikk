"""Flask application entrypoint and routes for the SIEM dashboard."""

from __future__ import annotations

import csv
import json
import os
import platform
import subprocess
from datetime import datetime, timezone
from io import StringIO
from typing import Any, Dict, List, Optional, cast

from flask import (
    Flask,
    Response,
    jsonify,
    redirect,
    render_template,
    request,
    url_for,
)
from dotenv import load_dotenv
from flask_login import (  # type: ignore[import-untyped]
    LoginManager,
    current_user,
    login_required,
    login_user,
    logout_user,
)

from audit_log import get_audit_log, log_user_action
from models import User, db

load_dotenv()

app = Flask(__name__)
app.config["SECRET_KEY"] = os.getenv("SECRET_KEY", "dev-secret-key")
app.config["SQLALCHEMY_DATABASE_URI"] = os.getenv(
    "DATABASE_URL", "sqlite:///users.db"
)
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
db.init_app(app)

DATA_DIR = os.path.join("static", "data")

SEVERITY_WEIGHTS: Dict[str, float] = {
    "critical": 8.0,
    "high": 5.0,
    "medium": 3.0,
    "low": 1.0,
    "info": 0.5,
}

VULNERABILITY_STATUS_MULTIPLIER: Dict[str, float] = {
    "open": 1.0,
    "in_progress": 0.6,
    "fixed": 0.0,
}

SUSPICIOUS_STATUS_CODES = {
    400,
    401,
    403,
    404,
    405,
    408,
    409,
    422,
    429,
    500,
    502,
    503,
    504,
}

SUSPICIOUS_ENDPOINT_PATTERNS = (
    "../",
    "<script",
    " union ",
    "' or '",
    '" or "',
    "/etc/passwd",
)

# Initialize Flask-Login
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"


@login_manager.user_loader
def load_user(user_id: str) -> Optional[User]:
    """Load a user record from the session user id."""
    try:
        user_id_int = int(user_id)
    except (TypeError, ValueError):
        return None
    return db.session.get(User, user_id_int)


def load_data(file_name: str) -> List[Dict[str, Any]]:
    """Load JSON array data from the static data directory."""
    file_path = os.path.join(DATA_DIR, f"{file_name}.json")
    with open(file_path, "r", encoding="utf-8") as data_file:
        data = json.load(data_file)
    if isinstance(data, list):
        return cast(List[Dict[str, Any]], data)
    return []


def load_data_safely(file_name: str) -> List[Dict[str, Any]]:
    """Load JSON data and return an empty list on common IO/JSON failures."""
    try:
        return load_data(file_name)
    except (FileNotFoundError, json.JSONDecodeError, OSError):
        return []


def normalize_bool(value: Any) -> Optional[bool]:
    """Normalize mixed truthy/falsey values into bool or None."""
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        return bool(value)
    if isinstance(value, str):
        normalized = value.strip().lower()
        if normalized in {
            "true",
            "enabled",
            "on",
            "yes",
            "1",
            "protectionon",
            "protected",
        }:
            return True
        if normalized in {
            "false",
            "disabled",
            "off",
            "no",
            "0",
            "protectionoff",
            "unprotected",
        }:
            return False
    return None


def parse_iso_datetime(value: str) -> Optional[datetime]:
    """Parse an ISO datetime and normalize it to UTC."""
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        return parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def run_powershell_json(command: str) -> Optional[Any]:
    """Run a PowerShell command and decode JSON output safely."""
    try:
        completed = subprocess.run(
            [
                "powershell",
                "-NoProfile",
                "-NonInteractive",
                "-Command",
                f"{command} | ConvertTo-Json -Compress",
            ],
            capture_output=True,
            text=True,
            timeout=5,
            check=False,
        )
    except (subprocess.SubprocessError, OSError):
        return None

    if completed.returncode != 0:
        return None

    payload = completed.stdout.strip()
    if not payload:
        return None

    try:
        return json.loads(payload)
    except json.JSONDecodeError:
        return None


def collect_system_security_signals() -> Dict[str, Any]:
    """Collect host security controls used by security score calculations."""
    signals: Dict[str, Any] = {"platform": platform.system()}
    if signals["platform"] != "Windows":
        return signals

    firewall_profiles = run_powershell_json(
        "Get-NetFirewallProfile | Select-Object Name,Enabled"
    )
    if firewall_profiles is not None:
        profiles = (
            firewall_profiles
            if isinstance(firewall_profiles, list)
            else [firewall_profiles]
        )
        profile_flags = [
            normalize_bool(profile.get("Enabled"))
            for profile in profiles
            if isinstance(profile, dict)
        ]
        known_flags = [flag for flag in profile_flags if flag is not None]
        if known_flags:
            signals["firewall_profiles_total"] = len(known_flags)
            signals["firewall_profiles_enabled"] = sum(
                1 for flag in known_flags if flag
            )

    defender_status = run_powershell_json(
        "Get-MpComputerStatus | Select-Object "
        "RealTimeProtectionEnabled,AntivirusEnabled,"
        "AntispywareEnabled,AntivirusSignatureLastUpdated"
    )
    if isinstance(defender_status, dict):
        signals["realtime_protection"] = normalize_bool(
            defender_status.get("RealTimeProtectionEnabled")
        )
        signals["antivirus_enabled"] = normalize_bool(
            defender_status.get("AntivirusEnabled")
        )
        signals["antispyware_enabled"] = normalize_bool(
            defender_status.get("AntispywareEnabled")
        )

        signature_last_updated = defender_status.get(
            "AntivirusSignatureLastUpdated"
        )
        if isinstance(signature_last_updated, str):
            parsed_signature_date = parse_iso_datetime(signature_last_updated)
            if parsed_signature_date:
                signature_age_hours = (
                    datetime.now(timezone.utc) - parsed_signature_date
                ).total_seconds() / 3600
                signals["signature_age_hours"] = round(
                    max(signature_age_hours, 0.0), 1
                )

    bitlocker_status = run_powershell_json(
        "Get-BitLockerVolume -MountPoint $env:SystemDrive | "
        "Select-Object ProtectionStatus"
    )
    if isinstance(bitlocker_status, list):
        bitlocker_status = bitlocker_status[0] if bitlocker_status else None
    if isinstance(bitlocker_status, dict):
        signals["disk_encryption_enabled"] = normalize_bool(
            bitlocker_status.get("ProtectionStatus")
        )

    return signals


def get_risk_level(score: int) -> str:
    """Convert a 0-100 score into a qualitative risk label."""
    if score >= 80:
        return "Low"
    if score >= 60:
        return "Moderate"
    if score >= 40:
        return "High"
    return "Critical"


# pylint: disable=too-many-locals,too-many-branches
def calculate_security_score(
    blocked_ips_data: List[Dict[str, Any]],
    logs_data: List[Dict[str, Any]],
    vulnerabilities_data: List[Dict[str, Any]],
) -> Dict[str, Any]:
    """Calculate an overall security score from telemetry and host controls."""
    active_vulnerability_penalty = 0.0
    for vulnerability in vulnerabilities_data:
        status = str(vulnerability.get("status", "")).lower()
        severity = str(vulnerability.get("severity", "")).lower()
        status_multiplier = VULNERABILITY_STATUS_MULTIPLIER.get(status, 1.0)
        severity_weight = SEVERITY_WEIGHTS.get(severity, 1.0)
        active_vulnerability_penalty += severity_weight * status_multiplier
    active_vulnerability_penalty = min(active_vulnerability_penalty, 45.0)

    suspicious_requests = 0
    total_requests = len(logs_data)
    for log in logs_data:
        status_code = log.get("status_code")
        endpoint = str(log.get("endpoint", "")).lower()
        suspicious_status = (
            isinstance(status_code, int)
            and status_code in SUSPICIOUS_STATUS_CODES
        )
        suspicious_endpoint = any(
            pattern in endpoint for pattern in SUSPICIOUS_ENDPOINT_PATTERNS
        )
        if suspicious_status or suspicious_endpoint:
            suspicious_requests += 1

    suspicious_request_ratio = (
        suspicious_requests / total_requests if total_requests else 0.0
    )
    suspicious_request_penalty = min(suspicious_request_ratio * 20.0, 20.0)

    severe_blocked_ips = sum(
        1
        for blocked_ip in blocked_ips_data
        if str(blocked_ip.get("severity", "")).lower() in {"critical", "high"}
    )
    blocked_threat_penalty = min(float(severe_blocked_ips), 10.0)

    system_signals = collect_system_security_signals()
    system_control_penalty = 0.0
    known_system_controls = 0

    firewall_profiles_total = system_signals.get("firewall_profiles_total")
    firewall_profiles_enabled = system_signals.get("firewall_profiles_enabled")
    if (
        isinstance(firewall_profiles_total, int)
        and isinstance(firewall_profiles_enabled, int)
        and firewall_profiles_total > 0
    ):
        known_system_controls += 1
        disabled_profiles = max(
            firewall_profiles_total - firewall_profiles_enabled, 0
        )
        if disabled_profiles == firewall_profiles_total:
            system_control_penalty += 15.0
        elif disabled_profiles > 0:
            system_control_penalty += 6.0

    for signal_name, penalty in [
        ("realtime_protection", 12.0),
        ("antivirus_enabled", 8.0),
        ("antispyware_enabled", 5.0),
        ("disk_encryption_enabled", 5.0),
    ]:
        signal_value = system_signals.get(signal_name)
        if isinstance(signal_value, bool):
            known_system_controls += 1
            if not signal_value:
                system_control_penalty += penalty

    signature_age_hours = system_signals.get("signature_age_hours")
    if isinstance(signature_age_hours, (int, float)):
        known_system_controls += 1
        if signature_age_hours > 168:
            system_control_penalty += 8.0
        elif signature_age_hours > 72:
            system_control_penalty += 4.0

    if (
        system_signals.get("platform") == "Windows"
        and known_system_controls == 0
    ):
        system_control_penalty += 2.0

    total_penalty = (
        active_vulnerability_penalty
        + suspicious_request_penalty
        + blocked_threat_penalty
        + system_control_penalty
    )
    score = int(round(max(0.0, min(100.0, 100.0 - total_penalty))))
    risk_level = get_risk_level(score)

    return {
        "score": score,
        "risk_level": risk_level,
        "updated_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "components": {
            "active_vulnerability_penalty": round(
                active_vulnerability_penalty, 2
            ),
            "suspicious_request_penalty": round(suspicious_request_penalty, 2),
            "blocked_threat_penalty": round(blocked_threat_penalty, 2),
            "system_control_penalty": round(system_control_penalty, 2),
            "suspicious_request_ratio": round(suspicious_request_ratio, 4),
            "severe_blocked_ips": severe_blocked_ips,
            "known_system_controls": known_system_controls,
        },
    }


def get_dashboard_metrics() -> Dict[str, Any]:
    """Aggregate top-level dashboard metric values."""
    blocked_ips_data = load_data_safely("blocked_ips")
    logs_data = load_data_safely("access_logs")
    vulnerabilities_data = load_data_safely("vulnerabilities")
    active_vulnerabilities = sum(
        1
        for vulnerability in vulnerabilities_data
        if str(vulnerability.get("status", "")).lower()
        in {"open", "in_progress"}
    )
    return {
        "blocked_ips_count": len(blocked_ips_data),
        "access_attempts_count": len(logs_data),
        "active_vulnerabilities_count": active_vulnerabilities,
        "security_score": calculate_security_score(
            blocked_ips_data, logs_data, vulnerabilities_data
        ),
    }


def calculate_blocked_ip_metrics(
    blocked_ips_data: List[Dict[str, Any]],
) -> Dict[str, Any]:
    """Compute summary metrics for the blocked IP page."""
    severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    unique_countries = set()
    total_hits = 0

    for blocked_ip in blocked_ips_data:
        severity = str(blocked_ip.get("severity", "low")).lower()
        if severity in severity_counts:
            severity_counts[severity] += 1

        country = blocked_ip.get("country")
        if isinstance(country, str) and country.strip():
            unique_countries.add(country.strip())

        hits = blocked_ip.get("hits", 0)
        if isinstance(hits, (int, float)):
            total_hits += int(hits)

    return {
        "total_blocked_ips": len(blocked_ips_data),
        "critical_blocked_ips": severity_counts["critical"],
        "high_blocked_ips": severity_counts["high"],
        "countries_impacted": len(unique_countries),
        "total_block_hits": total_hits,
    }


def calculate_access_log_metrics(
    logs_data: List[Dict[str, Any]],
) -> Dict[str, Any]:
    """Compute request/error/latency metrics for access logs."""
    total_requests = len(logs_data)
    success_requests = 0
    error_requests = 0
    total_response_time = 0
    response_time_count = 0

    for log in logs_data:
        status_code = log.get("status_code")
        if isinstance(status_code, int):
            if 200 <= status_code < 400:
                success_requests += 1
            elif 400 <= status_code < 600:
                error_requests += 1

        response_time = log.get("response_time")
        if isinstance(response_time, (int, float)):
            total_response_time += int(response_time)
            response_time_count += 1

    success_rate = (
        (success_requests / total_requests * 100)
        if total_requests
        else 0.0
    )
    error_rate = (
        (error_requests / total_requests * 100)
        if total_requests
        else 0.0
    )
    avg_response_time = (
        total_response_time / response_time_count
        if response_time_count
        else 0.0
    )

    return {
        "total_requests": total_requests,
        "success_rate": round(success_rate, 1),
        "error_rate": round(error_rate, 1),
        "avg_response_time_ms": int(round(avg_response_time)),
    }


def calculate_vulnerability_metrics(
    vulnerabilities_data: List[Dict[str, Any]],
) -> Dict[str, Any]:
    """Compute vulnerability counts by severity and workflow state."""
    severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    status_counts = {"open": 0, "in_progress": 0, "fixed": 0}

    for vulnerability in vulnerabilities_data:
        status = str(vulnerability.get("status", "")).lower()
        severity = str(vulnerability.get("severity", "")).lower()
        if status in status_counts:
            status_counts[status] += 1
        if status in {"open", "in_progress"} and severity in severity_counts:
            severity_counts[severity] += 1

    return {
        "critical_active": severity_counts["critical"],
        "high_active": severity_counts["high"],
        "medium_active": severity_counts["medium"],
        "low_active": severity_counts["low"],
        "open_total": status_counts["open"],
        "in_progress_total": status_counts["in_progress"],
        "fixed_total": status_counts["fixed"],
        "active_total": status_counts["open"] + status_counts["in_progress"],
    }


def calculate_audit_metrics(
    audit_entries: List[Dict[str, Any]],
) -> Dict[str, Any]:
    """Compute summary information for audit events."""
    unique_users = set()
    export_actions = 0

    for entry in audit_entries:
        user = entry.get("user")
        if user is not None:
            unique_users.add(str(user))
        action = str(entry.get("action", "")).lower()
        if action.startswith("export_"):
            export_actions += 1

    return {
        "total_entries": len(audit_entries),
        "unique_users": len(unique_users),
        "export_actions": export_actions,
    }


def build_csv_response(
    rows: List[Dict[str, Any]], filename: str
) -> Response:
    """Build a CSV file response from a list of dictionaries."""
    csv_buffer = StringIO()
    if rows:
        fieldnames = list(rows[0].keys())
        writer = csv.DictWriter(csv_buffer, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)

    return app.response_class(
        csv_buffer.getvalue(),
        mimetype="text/csv",
        headers={"Content-Disposition": f"attachment;filename={filename}"},
    )


def bootstrap_application() -> None:
    """Initialize data directory, database tables, and default admin user."""
    os.makedirs(DATA_DIR, exist_ok=True)
    with app.app_context():
        db.create_all()
        default_admin_username = os.getenv("DEFAULT_ADMIN_USERNAME", "admin")
        default_admin_email = os.getenv(
            "DEFAULT_ADMIN_EMAIL", "admin@example.com"
        )
        default_admin_password = os.getenv(
            "DEFAULT_ADMIN_PASSWORD", "password"
        )
        if not User.query.filter_by(username=default_admin_username).first():
            admin_user = User(
                username=default_admin_username,
                email=default_admin_email,
            )
            admin_user.set_password(default_admin_password)
            db.session.add(admin_user)
            db.session.commit()


@app.route("/login", methods=["GET", "POST"])
def login():
    """Authenticate a user and start a session."""
    if current_user.is_authenticated:
        return redirect(url_for("index"))

    if request.method == "POST":
        username = (request.form.get("username") or "").strip()
        password = request.form.get("password") or ""
        remember = request.form.get("remember") == "on"
        next_page = request.form.get("next") or request.args.get("next")

        if next_page and not next_page.startswith("/"):
            next_page = None

        user = User.query.filter_by(username=username).first()
        if user and user.check_password(password):
            login_user(user, remember=remember)
            return redirect(next_page or url_for("index"))

        return render_template("login.html", error="Invalid credentials")

    return render_template("login.html")


@app.route("/logout")
@login_required
def logout():
    """Terminate the active session."""
    logout_user()
    return redirect(url_for("login"))


@app.route("/")
@login_required
def index():
    """Render dashboard home page."""
    metrics = get_dashboard_metrics()
    return render_template(
        "dashboard.html",
        active_page="dashboard",
        blocked_ips_count=metrics["blocked_ips_count"],
        access_attempts_count=metrics["access_attempts_count"],
        active_vulnerabilities_count=metrics["active_vulnerabilities_count"],
        security_score=metrics["security_score"],
    )


@app.route("/blocked_ips")
@login_required
def blocked_ips():
    """Render blocked IPs page."""
    blocked_ips_data = load_data_safely("blocked_ips")
    blocked_ip_metrics = calculate_blocked_ip_metrics(blocked_ips_data)
    return render_template(
        "blocked_ips.html",
        blocked_ips=blocked_ips_data,
        blocked_ip_metrics=blocked_ip_metrics,
        active_page="blocked_ips",
    )


@app.route("/access_logs")
@login_required
def access_logs():
    """Render access logs page."""
    logs_data = load_data_safely("access_logs")
    access_metrics = calculate_access_log_metrics(logs_data)
    return render_template(
        "access_logs.html",
        logs=logs_data,
        access_metrics=access_metrics,
        active_page="access_logs",
    )


@app.route("/vulnerabilities")
@login_required
def vulnerabilities():
    """Render vulnerabilities page."""
    vulnerability_data = load_data_safely("vulnerabilities")
    vulnerability_metrics = calculate_vulnerability_metrics(vulnerability_data)
    return render_template(
        "vulnerabilities.html",
        vulnerabilities=vulnerability_data,
        vulnerability_metrics=vulnerability_metrics,
        active_page="vulnerabilities",
    )


@app.route("/api/data/<data_type>")
def get_data(data_type: str):
    """Serve raw JSON data for the requested data_type."""
    try:
        data = load_data(data_type)
        return jsonify(data)
    except (FileNotFoundError, json.JSONDecodeError, OSError):
        return jsonify({"error": "Data not found"}), 404


@app.route("/api/security_score")
@login_required
def api_security_score():
    """Serve calculated security score as JSON."""
    metrics = get_dashboard_metrics()
    return jsonify(metrics["security_score"])


@app.route("/toggle_theme", methods=["POST"])
def toggle_theme():
    """Persist selected UI theme in a cookie."""
    theme = request.form.get("theme")
    response = redirect(request.referrer or url_for("index"))
    if theme:
        response.set_cookie("theme", theme, max_age=60 * 60 * 24 * 365)
    return response


@app.route("/export_logs")
@login_required
def export_logs():
    """Export access logs to CSV."""
    logs_data = load_data_safely("access_logs")
    log_user_action(current_user.id, "export_logs")
    return build_csv_response(logs_data, "access_logs.csv")


@app.route("/export_blocked_ips")
@login_required
def export_blocked_ips():
    """Export blocked IP data to CSV."""
    blocked_ips_data = load_data_safely("blocked_ips")
    log_user_action(current_user.id, "export_blocked_ips")
    return build_csv_response(blocked_ips_data, "blocked_ips.csv")


@app.route("/export_vulnerabilities")
@login_required
def export_vulnerabilities():
    """Export vulnerability data to CSV."""
    vulnerability_data = load_data_safely("vulnerabilities")
    log_user_action(current_user.id, "export_vulnerabilities")
    return build_csv_response(vulnerability_data, "vulnerabilities.csv")


@app.route("/export_audit_log")
@login_required
def export_audit_log():
    """Export audit log entries to CSV."""
    audit_data = cast(List[Dict[str, Any]], get_audit_log())
    log_user_action(current_user.id, "export_audit_log")
    return build_csv_response(audit_data, "audit_log.csv")


@app.route("/audit_log")
@login_required
def audit_log():
    """Render audit log page."""
    audit_data = cast(List[Dict[str, Any]], get_audit_log())
    audit_metrics = calculate_audit_metrics(audit_data)
    return render_template(
        "audit_log.html",
        audit_log=audit_data,
        audit_metrics=audit_metrics,
        active_page="audit_log",
    )


@app.route("/health")
def health() -> Response:
    """Lightweight health check endpoint for deploy targets."""
    return jsonify({"status": "ok", "service": "siem-dashboard"})


@app.route("/register", methods=["GET", "POST"])
# pylint: disable=too-many-return-statements
def register():
    """Create a new user account and sign in the user."""
    # pylint: disable=too-many-return-statements
    if request.method == "POST":
        username = (request.form.get("username") or "").strip()
        email = (request.form.get("email") or "").strip()
        password = request.form.get("password") or ""
        confirm_password = request.form.get("confirm_password") or ""

        if not username:
            return render_template(
                "register.html", error="Username is required"
            )
        if not email:
            return render_template("register.html", error="Email is required")
        if User.query.filter_by(username=username).first():
            return render_template(
                "register.html", error="Username already exists"
            )
        if User.query.filter_by(email=email).first():
            return render_template(
                "register.html", error="Email already exists"
            )
        if password != confirm_password:
            return render_template(
                "register.html", error="Passwords do not match"
            )
        if len(password) < 6:
            return render_template(
                "register.html",
                error="Password must be at least 6 characters",
            )

        new_user = User(username=username, email=email)
        new_user.set_password(password)
        db.session.add(new_user)
        db.session.commit()
        login_user(new_user)
        return redirect(url_for("index"))

    return render_template("register.html")


if __name__ == "__main__":
    bootstrap_application()
    host = os.getenv("HOST", "0.0.0.0")
    port = int(os.getenv("PORT", "5000"))
    debug = os.getenv("FLASK_DEBUG", "0") in {"1", "true", "True"}
    app.run(host=host, port=port, debug=debug)
