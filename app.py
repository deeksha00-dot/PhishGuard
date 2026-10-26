"""
app.py - Flask backend for PhishGuard.

Run locally with:  python app.py   then open http://127.0.0.1:5000
"""

import os

from flask import Flask, jsonify, render_template, request

import database
from detector import VALID_INPUT_TYPES, analyze_content

MAX_TEXT_LENGTH = 10_000


def create_app(db_path=None):
    """Application factory. Tests pass a temporary db_path; normal runs use phishguard.db."""
    app = Flask(__name__)
    app.config["DB_PATH"] = db_path or database.DEFAULT_DB_PATH
    app.config["MAX_CONTENT_LENGTH"] = 128 * 1024  # reject huge request bodies early
    database.init_db(app.config["DB_PATH"])  # tables are created automatically

    def error(message, status):
        return jsonify({"error": message}), status

    # ---------------- Pages ----------------
    @app.route("/")
    def index():
        return render_template("index.html", max_length=MAX_TEXT_LENGTH)

    # ---------------- API ----------------
    @app.route("/api/health", methods=["GET"])
    def health():
        return jsonify({"status": "ok", "service": "PhishGuard"})

    @app.route("/api/analyze", methods=["POST"])
    def analyze():
        data = request.get_json(silent=True)
        if not isinstance(data, dict):
            return error("Request body must be valid JSON, e.g. {\"text\": \"...\"}.", 400)

        text = data.get("text")
        input_type = data.get("input_type", "auto")
        if not isinstance(text, str):
            return error("Field 'text' is required and must be a string.", 400)
        if not text.strip():
            return error("Please paste a message or URL to analyze.", 400)
        if len(text) > MAX_TEXT_LENGTH:
            return error(f"Content is too long. The maximum is {MAX_TEXT_LENGTH:,} characters.", 413)
        if input_type not in VALID_INPUT_TYPES:
            return error("Field 'input_type' must be one of: " + ", ".join(VALID_INPUT_TYPES) + ".", 400)

        result = analyze_content(text, input_type)
        try:
            analysis_id = database.save_analysis(text, result, app.config["DB_PATH"])
        except database.DatabaseError:
            return error("The analysis finished but could not be saved. Please try again.", 500)

        result["id"] = analysis_id
        return jsonify(result), 200

    @app.route("/api/history", methods=["GET"])
    def history():
        try:
            return jsonify({"history": database.get_recent(db_path=app.config["DB_PATH"])})
        except database.DatabaseError:
            return error("Could not load the history.", 500)

    @app.route("/api/history/<int:analysis_id>", methods=["GET"])
    def history_item(analysis_id):
        try:
            item = database.get_analysis(analysis_id, app.config["DB_PATH"])
        except database.DatabaseError:
            return error("Could not load that analysis.", 500)
        if item is None:
            return error("Analysis not found.", 404)
        return jsonify(item)

    @app.route("/api/history", methods=["DELETE"])
    def clear_history():
        try:
            deleted = database.clear_history(app.config["DB_PATH"])
        except database.DatabaseError:
            return error("Could not clear the history.", 500)
        return jsonify({"deleted": deleted})

    # ---------------- Error handlers (JSON for the API) ----------------
    @app.errorhandler(404)
    def not_found(_):
        if request.path.startswith("/api/"):
            return error("Endpoint not found.", 404)
        return "Page not found", 404

    @app.errorhandler(405)
    def method_not_allowed(_):
        return error("Method not allowed.", 405)

    @app.errorhandler(413)
    def too_large(_):
        return error("Request is too large.", 413)

    @app.errorhandler(500)
    def server_error(_):
        return error("Something went wrong on the server.", 500)

    return app


app = create_app()

if __name__ == "__main__":
    # Debug mode is OFF by default. Set PHISHGUARD_DEBUG=1 only for local development.
    app.run(host="127.0.0.1", port=5000, debug=os.environ.get("PHISHGUARD_DEBUG") == "1")
