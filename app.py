import os
from flask import Flask, render_template, request, redirect, url_for, session
from utils.helpers import (
    init_db,
    add_alert,
    get_all_alerts,
    delete_alert,
    parse_log_file,
    get_alerts_by_severity,
    scan_common_ports,
    save_scan_result,
    get_all_scans,
    is_valid_ip
)

app = Flask(__name__)
app.config["UPLOAD_FOLDER"] = "uploads"
app.secret_key = "change-this-to-a-secure-random-secret-key"


@app.route("/")
def home():
    if "user" in session:
        return redirect(url_for("dashboard"))
    return redirect(url_for("login"))


@app.route("/login", methods=["GET", "POST"])
def login():
    error = None

    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")

        if username == "admin" and password == "password123":
            session["user"] = username
            return redirect(url_for("dashboard"))
        else:
            error = "Invalid username or password."

    return render_template("login.html", error=error)


@app.route("/logout")
def logout():
    session.pop("user", None)
    return redirect(url_for("login"))


@app.route("/dashboard", methods=["GET", "POST"])
def dashboard():
    if "user" not in session:
        return redirect(url_for("login"))

    scan_results = []

    if request.method == "POST":

        if "log_file" in request.files and request.files["log_file"].filename != "":
            log_file = request.files["log_file"]
            file_path = os.path.join(app.config["UPLOAD_FOLDER"], log_file.filename)
            log_file.save(file_path)

            parsed_alerts = parse_log_file(file_path)
            for alert in parsed_alerts:
                add_alert(alert["alert_type"], alert["severity"], alert["message"])

            return redirect(url_for("dashboard"))

        if request.form.get("target_ip"):
            target_ip = request.form.get("target_ip")

            if not is_valid_ip(target_ip):
                add_alert(
                    "Invalid Input",
                    "Low",
                    f"Invalid IP address entered: {target_ip}"
                )
                return redirect(url_for("dashboard"))

            scan_results = scan_common_ports(target_ip)

            if scan_results:
                for result in scan_results:
                    save_scan_result(target_ip, result)
            else:
                save_scan_result(target_ip, "No common open ports detected")

            return redirect(url_for("dashboard"))

        alert_type = request.form.get("alert_type")
        severity = request.form.get("severity")
        message = request.form.get("message")

        if alert_type and severity and message:
            add_alert(alert_type, severity, message)

        return redirect(url_for("dashboard"))

    selected_severity = request.args.get("severity", "All")

    if selected_severity == "All":
        alerts = get_all_alerts()
    else:
        alerts = get_alerts_by_severity(selected_severity)

    scans = get_all_scans()

    return render_template(
        "dashboard.html",
        alerts=alerts,
        selected_severity=selected_severity,
        scan_results=scan_results,
        scans=scans
    )


@app.route("/delete_alert/<int:alert_id>", methods=["POST"])
def remove_alert(alert_id):
    if "user" not in session:
        return redirect(url_for("login"))

    delete_alert(alert_id)
    return redirect(url_for("dashboard"))


if __name__ == "__main__":
    init_db()
    app.run(debug=True)