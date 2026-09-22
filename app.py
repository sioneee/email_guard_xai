import hashlib

from explainers.proximity import build_explanation
from renderers.korean import render_explanation
from flask import Flask, jsonify, request
from flask_cors import CORS

from adapters.knn295 import Knn295Detector

app = Flask(__name__)
app.json.ensure_ascii = False
app.config["MAX_CONTENT_LENGTH"] = 50 * 1024 * 1024

CORS(app)

detector = None
startup_error = None

try:
    detector = Knn295Detector()
except Exception as error:
    startup_error = f"{type(error).__name__}: {error}"


@app.get("/health")
def health():
    if startup_error:
        return jsonify({
            "status": "error",
            "message": startup_error
        }), 503

    return jsonify({
        "status": "ok",
        "detector": "knn295"
    })


@app.post("/v1/explanations")
def explanations():
    if startup_error:
        return jsonify({
            "error": startup_error
        }), 503

    uploaded_file = request.files.get("file")

    if uploaded_file is None:
        return jsonify({
            "error": "file 항목이 필요합니다."
        }), 400

    file_bytes = uploaded_file.read()
    result = detector.analyze(file_bytes)

    result["explanation"] = None

    if result["verdict"] == "suspicious":
        technical_result = build_explanation(detector, file_bytes)
        result["explanation"] = render_explanation(technical_result)

    result["filename"] = uploaded_file.filename
    result["sha256"] = hashlib.sha256(file_bytes).hexdigest()

    return jsonify(result)


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5001, debug=True)