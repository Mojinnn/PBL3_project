
#!/usr/bin/env python3
# app.py — Flask dashboard for Pi NetWatch
from flask import Flask, render_template_string, jsonify
import pandas as pd
import os

app = Flask(__name__)

# Files produced by your probes / merger
MERGED_CSV = "data/merged_summary.csv"    # produced by main.py (merged Scapy + TShark + Ping)
TRAFFIC_CSV = "data/traffic_probe.csv"    # Scapy probe (if you want direct)
TSHARK_CSV = "data/tshark_probe.csv"      # tshark probe

# HTML template (keeps layout similar to your previous dashboard)
TEMPLATE = """
<!doctype html>
<html>
<head>
<meta charset="utf-8">
<title>Pi NetWatch — Dashboard</title>
<script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
<style>
body { font-family: Inter, Arial, sans-serif; margin:12px; background:#f6f7fb; color:#111; }
h1 { text-align:center; margin-bottom:8px; }
.donut-row { display:flex; gap:18px; flex-wrap:nowrap; justify-content:center; overflow-x:auto; padding-bottom:6px; }
.card { background:#fff; border-radius:12px; box-shadow:0 4px 18px rgba(20,20,40,0.06); padding:14px; }
.donut-card { flex:0 0 auto; width:300px; padding:10px; text-align:center; min-height:260px; display:flex; flex-direction:column; justify-content:flex-start; }
.donut-card canvas { width:260px !important; height:200px !important; }
.chart-card { width:90%; max-width:1000px; margin:10px auto; padding:12px; }
.chart-card canvas { width:100% !important; max-height:240px !important; height:240px !important; display:block; }
.label { font-weight:600; margin-bottom:6px; display:block; }
.kpi { font-size:18px; margin-top:8px; }
@media (max-width:900px){ .donut-card{ width:48%; } .chart-card{ width:95%; } }
@media (max-width:520px){ .donut-card{ width:100%; } }
</style>
</head>
<body>
<h1>📡 Pi NetWatch — Dashboard</h1>

<div class="donut-row" style="margin-bottom:14px;">
  <div class="card donut-card">
    <div class="label">Ping: Success vs Loss (%)</div>
    <canvas id="pingDonut"></canvas>
    <div class="kpi" id="ping_kpi"></div>
  </div>

  <div class="card donut-card">
    <div class="label">Traffic (Scapy): Proto distribution (pkts)</div>
    <canvas id="trafficDonut"></canvas>
    <div class="kpi" id="traffic_kpi"></div>
  </div>

  <div class="card donut-card">
    <div class="label">TShark: Proto distribution (pkts)</div>
    <canvas id="tsharkDonut"></canvas>
    <div class="kpi" id="tshark_kpi"></div>
  </div>
</div>

<div class="chart-card card">
  <div class="label">Ping — Latency (ms) & Loss (%)</div>
  <canvas id="pingChart"></canvas>
</div>

<div class="chart-card card">
  <div class="label">Traffic (Scapy) — Total Packets & Bytes</div>
  <canvas id="trafficChart"></canvas>
</div>

<div class="chart-card card">
  <div class="label">TShark — Packets & Bytes</div>
  <canvas id="tsharkChart"></canvas>
</div>

<script>
const protoColors=['#2ca8ff','#ff6b8a','#ffb463','#ffe07a'];

function mkDonut(el){
  return new Chart(document.getElementById(el), {
    type:'doughnut',
    data:{labels:['TCP','UDP','ICMP','Other'], datasets:[{data:[0,0,0,0], backgroundColor:protoColors, borderColor:'#fff', borderWidth:2}]},
    options:{maintainAspectRatio:false, plugins:{legend:{position:'top'}}}
  });
}

const pingDonut = new Chart(document.getElementById('pingDonut'), {
  type:'doughnut',
  data:{labels:['Success %','Loss %'], datasets:[{data:[100,0], backgroundColor:['#2ca8ff','#ff6b8a'], borderColor:'#fff', borderWidth:2}]},
  options:{maintainAspectRatio:false, plugins:{legend:{position:'top'}}}
});
const trafficDonut = mkDonut('trafficDonut');
const tsharkDonut = mkDonut('tsharkDonut');

// Line charts
function mkLine(el, labels=[], datasetDefs=[]){
  return new Chart(document.getElementById(el), {
    type:'line',
    data:{labels:labels, datasets: datasetDefs},
    options:{responsive:true, maintainAspectRatio:false, plugins:{legend:{position:'top'}}, scales:{x:{ticks:{autoSkip:true,maxTicksLimit:10}}}}
  });
}

const pingChart = mkLine('pingChart', [], [
  {label:'Latency (ms)', data:[], borderWidth:2, tension:0.3, fill:false},
  {label:'Loss (%)', data:[], borderWidth:2, tension:0.3, fill:false}
]);

const trafficChart = mkLine('trafficChart', [], [
  {label:'Total Packets', data:[], borderWidth:2, tension:0.3, fill:false},
  {label:'Total Bytes', data:[], borderWidth:2, tension:0.3, fill:false}
]);

const tsharkChart = mkLine('tsharkChart', [], [
  {label:'TShark Packets', data:[], borderWidth:2, tension:0.3, fill:false},
  {label:'TShark Bytes', data:[], borderWidth:2, tension:0.3, fill:false}
]);

// fetch helpers
async function fetchJson(url){ try{ const r=await fetch(url); return r.ok?await r.json():null } catch(e){ console.warn(e); return null } }

// Update functions (traffic uses merged_summary as source of truth)
async function updateDonuts(){
  // merged summary gives traffic (scapy fields) and ping
  const merged = await fetchJson('/api/summary');
  const latest = (merged && merged.length>0)? merged[merged.length-1] : null;

  // ping donut
  if(latest){
    const loss = Number(latest.loss_percent||0);
    const success = Math.max(0,100-loss);
    pingDonut.data.datasets[0].data = [success, loss];
    pingDonut.update();
    document.getElementById('ping_kpi').innerText = `Latency ${latest.latency_ms||'N/A'} ms • Jitter ${latest.jitter_ms||'N/A'} ms`;
  }

  // traffic donut (Scapy) — read from merged fields
  if(latest){
    const tcp = Number(latest.tcp||0), udp = Number(latest.udp||0),
          icmp = Number(latest.icmp||0), other = Number(latest.other||0);
    const total_packets = tcp + udp + icmp + other;
  //  const sum = tcp+udp+icmp+other;
    // update donut only with numbers (avoid NaN)
    trafficDonut.data.datasets[0].data = [tcp,udp,icmp,other];
    trafficDonut.update();
    //const total_packets = Number(latest.total_packets||0);
    const total_bytes = Number(latest.total_bytes||0);
    document.getElementById('traffic_kpi').innerText = `Total packets: ${total_packets} • Bytes: ${total_bytes||'N/A'}`;
  }

  // tshark donut — call tshark API
  const tshark_latest = await fetchJson('/api/tshark_latest');
  if(tshark_latest && Object.keys(tshark_latest).length>0){
    const ttcp=Number(tshark_latest.tcp||0), tudp=Number(tshark_latest.udp||0),
          ticmp=Number(tshark_latest.icmp||0), tother=Number(tshark_latest.other||0);
    tsharkDonut.data.datasets[0].data = [ttcp,tudp,ticmp,tother];
    tsharkDonut.update();
    document.getElementById('tshark_kpi').innerText = `Total packets: ${tshark_latest.total_pkts||0} • Bytes: ${tshark_latest.total_bytes||'N/A'}`;
  } else {
    // show empty / N/A if no tshark data
    tsharkDonut.data.datasets[0].data = [0,0,0,0];
    tsharkDonut.update();
    document.getElementById('tshark_kpi').innerText = `TShark data unavailable`;
  }
}

async function updateLines(){
  const merged = await fetchJson('/api/summary') || [];
  const labels = merged.map(r => r.timestamp || '');
  // ping lines
  pingChart.data.labels = labels;
  pingChart.data.datasets[0].data = merged.map(r => Number(r.latency_ms||0));
  pingChart.data.datasets[1].data = merged.map(r => Number(r.loss_percent||0));
  pingChart.update();

  // traffic lines (Scapy totals)
  trafficChart.data.labels = labels;
  //trafficChart.data.datasets[0].data = merged.map(r => Number(r.total_packets||0));
  trafficChart.data.datasets[0].data = merged.map(r => 
    Number(r.tcp||0) + Number(r.udp||0) + Number(r.icmp||0) + Number(r.other||0)
);
  trafficChart.data.datasets[1].data = merged.map(r => Number(r.total_bytes||0));
  trafficChart.update();

  // tshark lines — use tshark summary endpoint
  const tshark_summary = await fetchJson('/api/tshark_summary') || [];
  const t_labels = tshark_summary.map(r => r.timestamp || '');
  tsharkChart.data.labels = t_labels;
  tsharkChart.data.datasets[0].data = tshark_summary.map(r => Number(r.total_pkts||0));
  tsharkChart.data.datasets[1].data = tshark_summary.map(r => Number(r.total_bytes||0));
  tsharkChart.update();
}

// initial + periodic
window.addEventListener('load', ()=>{
  updateDonuts();
  updateLines();
  setInterval(updateDonuts, 5000);
  setInterval(updateLines, 15000);
});
</script>
</body>
</html>
"""

# --------------------
# Helper loaders that normalize CSVs
# --------------------
def _load_csv_tail(path, tail=20, expected_cols=None):
    """Load CSV and return tail rows as list of dicts. Normalize column names and fallback defaults."""
    if not os.path.exists(path):
        return []
    try:
        # try reading with header
        df = pd.read_csv(path)
    except Exception:
        # fallback headerless: read with header=None then map by expected_cols
        try:
            df = pd.read_csv(path, header=None)
            if expected_cols:
                mapping = {i: expected_cols[i] for i in range(min(len(expected_cols), len(df.columns)))}
                df = df.rename(columns=mapping)
            else:
                # name numbered columns
                df.columns = [str(c) for c in df.columns]
        except Exception:
            return []

    # normalize column names: lower-case & strip
    df.columns = [str(c).strip().lower() for c in df.columns]

    # ensure expected columns exist
    if expected_cols:
        for c in expected_cols:
            if c not in df.columns:
                df[c] = 0

    # coerce numeric
    numcols = [c for c in df.columns if c not in ['timestamp','iface','interface']]
    for c in numcols:
        try:
            df[c] = pd.to_numeric(df[c], errors='coerce').fillna(0)
        except Exception:
            pass

    # tail and convert to records
    df = df.tail(tail).fillna(0)
    records = df.to_dict(orient='records')
    # ensure all values are serializable primitives
    for rec in records:
        for k,v in list(rec.items()):
            if pd.isna(v):
                rec[k] = 0
            elif isinstance(v, (float, int)):
                # if int-like, cast to int for nicer display
                if float(v).is_integer():
                    rec[k] = int(v)
                else:
                    rec[k] = float(v)
            else:
                rec[k] = v
    return records

# --------------------
# Routes
# --------------------
@app.route('/')
def index():
    return render_template_string(TEMPLATE)

@app.route('/api/summary')
def api_summary():
    # expected merged columns (as in merged main.py)
    expected = ["timestamp","latency_ms","jitter_ms","loss_percent",
                "total_packets","tcp","udp","icmp","other","total_bytes",
                "total_pkts","tshark_tcp","tshark_udp","tshark_icmp","tshark_other","tshark_bytes"]
    recs = _load_csv_tail(MERGED_CSV, tail=20, expected_cols=expected)
    return jsonify(recs)

@app.route('/api/traffic_summary')
def api_traffic_summary():
    expected = ["timestamp","iface","total_packets","tcp","udp","icmp","other","total_bytes"]
    recs = _load_csv_tail(TRAFFIC_CSV, tail=20, expected_cols=expected)
    # if traffic file empty, fallback to merged csv traffic fields
    if not recs:
        merged = _load_csv_tail(MERGED_CSV, tail=20, expected_cols=None)
        # map merged fields to traffic fields if present
        recs = []
        for r in merged:
            recs.append({
                "timestamp": r.get("timestamp",""),
                "iface": r.get("iface",""),
                "total_packets": int(r.get("total_packets",0)),
                "tcp": int(r.get("tcp",0)),
                "udp": int(r.get("udp",0)),
                "icmp": int(r.get("icmp",0)),
                "other": int(r.get("other",0)),
                "total_bytes": int(r.get("total_bytes",0))
            })
    return jsonify(recs)

@app.route('/api/traffic_latest')
def api_traffic_latest():
    recs = _load_csv_tail(TRAFFIC_CSV, tail=1, expected_cols=["timestamp","iface","total_packets","tcp","udp","icmp","other","total_bytes"])
    if recs:
        return jsonify(recs[-1])
    # fallback to merged
    merged = _load_csv_tail(MERGED_CSV, tail=1)
    if merged:
        m = merged[-1]
        return jsonify({
            "timestamp": m.get("timestamp",""),
            "iface": m.get("iface",""),
            "total_packets": int(m.get("total_packets",0)),
            "tcp": int(m.get("tcp",0)),
            "udp": int(m.get("udp",0)),
            "icmp": int(m.get("icmp",0)),
            "other": int(m.get("other",0)),
            "total_bytes": int(m.get("total_bytes",0))
        })
    return jsonify({})

@app.route('/api/tshark_summary')
def api_tshark_summary():
    expected = ["timestamp","iface","capture_time_s","total_pkts","tcp","udp","icmp","other","total_bytes"]
    recs = _load_csv_tail(TSHARK_CSV, tail=20, expected_cols=expected)
    # fallback to merged tshark fields if present
    if not recs:
        merged = _load_csv_tail(MERGED_CSV, tail=20)
        recs = []
        for r in merged:
            recs.append({
                "timestamp": r.get("timestamp",""),
                "iface": r.get("iface",""),
                "total_pkts": int(r.get("total_pkts",0)),
                "tcp": int(r.get("tshark_tcp", r.get("tcp",0))),
                "udp": int(r.get("tshark_udp", r.get("udp",0))),
                "icmp": int(r.get("tshark_icmp", r.get("icmp",0))),
                "other": int(r.get("tshark_other", r.get("other",0))),
                "total_bytes": int(r.get("tshark_bytes", r.get("total_bytes",0)))
            })
    return jsonify(recs)

@app.route('/api/tshark_latest')
def api_tshark_latest():
    recs = _load_csv_tail(TSHARK_CSV, tail=1, expected_cols=["timestamp","iface","capture_time_s","total_pkts","tcp","udp","icmp","other","total_bytes"])
    if recs:
        return jsonify(recs[-1])
    merged = _load_csv_tail(MERGED_CSV, tail=1)
    if merged:
        r = merged[-1]
        return jsonify({
            "timestamp": r.get("timestamp",""),
            "iface": r.get("iface",""),
            "total_pkts": int(r.get("total_pkts",0)),
            "tcp": int(r.get("tshark_tcp", r.get("tcp",0))),
            "udp": int(r.get("tshark_udp", r.get("udp",0))),
            "icmp": int(r.get("tshark_icmp", r.get("icmp",0))),
            "other": int(r.get("tshark_other", r.get("other",0))),
            "total_bytes": int(r.get("tshark_bytes", r.get("total_bytes",0)))
        })
    return jsonify({})

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=3000, debug=False)
