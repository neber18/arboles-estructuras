from flask import Flask, jsonify, render_template, request

from tree import ThreatTree

app = Flask(__name__)
tree = ThreatTree()

INITIAL_INCIDENTS = [
    ("150.20.10.5", 6, "Brute force"),
    ("45.33.12.9", 4, "Port scan"),
    ("192.168.0.77", 9, "SQL injection"),
    ("23.94.5.133", 5, "Phishing"),
    ("91.240.118.4", 8, "DDoS"),
    ("172.16.8.2", 10, "Malware C2"),
    ("203.0.113.45", 7, "Credential stuffing"),
    ("5.188.10.176", 6, "Brute force"),
    ("103.75.201.2", 3, "XSS"),
    ("185.220.101.4", 5, "Port scan"),
]

for ip, level, attack in INITIAL_INCIDENTS:
    tree.insert(ip, level, attack)


def snapshot():
    return {
        "tree": tree.to_dict(),
        "records": tree.in_order(),
        "stats": tree.stats(),
    }


@app.route("/")
def index():
    return render_template("index.html")


@app.get("/api/tree")
def get_tree():
    return jsonify(snapshot())


@app.post("/api/incidents")
def add_incident():
    data = request.get_json(silent=True) or {}
    try:
        level = int(data.get("threat_level", 0))
        if not 1 <= level <= 10:
            raise ValueError
        attack = str(data.get("attack_type", "")).strip() or "Unknown"
        tree.insert(str(data.get("ip", "")), level, attack)
    except (ValueError, TypeError):
        return jsonify({"error": "Invalid IP address or threat level"}), 400
    return jsonify(snapshot())


@app.get("/api/search")
def search_incident():
    try:
        node, path = tree.search(request.args.get("ip", ""))
    except ValueError:
        return jsonify({"error": "Invalid IP address"}), 400
    return jsonify({
        "found": node is not None,
        "record": node.as_dict() if node else None,
        "path": path,
        "total": tree.stats()["weight"],
    })


@app.delete("/api/incidents/<ip>")
def remove_incident(ip):
    try:
        removed = tree.delete(ip)
    except ValueError:
        return jsonify({"error": "Invalid IP address"}), 400
    if not removed:
        return jsonify({"error": "IP not found"}), 404
    return jsonify(snapshot())


if __name__ == "__main__":
    app.run(debug=True)
