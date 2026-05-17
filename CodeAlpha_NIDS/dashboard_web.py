"""
=============================================================================
 CodeAlpha Internship -- Task 4: Network Intrusion Detection System
 Module  : dashboard_web.py -- Flask REST API and web dashboard server
 Author  : Lbien Bilal
 GitHub  : github.com/b1l4l-sec
 Program : Cycle Ingenieur GDNC -- ENSA Fes
 Contact : lbienbilal@gmail.com
=============================================================================

Endpoints:
  GET /            Web dashboard (templates/dashboard.html)
  GET /api/alerts  Last 100 alerts as JSON
  GET /api/stats   Aggregate statistics, rule breakdown, timeline, top IPs
"""

from flask import Flask, render_template, jsonify
from collections import defaultdict
from datetime import datetime

from detector import DetectionEngine

app = Flask(__name__)
_engine: DetectionEngine = None


def set_engine(engine: DetectionEngine):
    global _engine
    _engine = engine


@app.route("/")
def index():
    return render_template("dashboard.html")


@app.route("/api/alerts")
def api_alerts():
    if not _engine:
        return jsonify([])
    return jsonify([a.to_dict() for a in _engine.get_recent_alerts(100)])


@app.route("/api/stats")
def api_stats():
    if not _engine:
        return jsonify({})

    stats  = _engine.get_stats()
    alerts = _engine.get_recent_alerts(500)

    rule_counts = defaultdict(int)
    ip_counts   = defaultdict(int)
    buckets     = defaultdict(int)

    for a in alerts:
        rule_counts[a.rule_name] += 1
        ip_counts[a.src_ip]      += 1
        try:
            key = datetime.strptime(a.timestamp, "%Y-%m-%d %H:%M:%S").strftime("%H:%M")
            buckets[key] += 1
        except ValueError:
            pass

    top_ips  = sorted(ip_counts.items(), key=lambda x: -x[1])[:10]
    timeline = dict(sorted(buckets.items())[-10:])

    return jsonify({
        "totals":   stats,
        "rules":    dict(rule_counts),
        "top_ips":  top_ips,
        "timeline": timeline,
    })


def run_web(host="0.0.0.0", port=5000):
    app.run(host=host, port=port, debug=False, use_reloader=False)