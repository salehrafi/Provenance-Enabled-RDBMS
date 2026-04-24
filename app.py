import sqlite3, os, json
from flask import Flask, render_template_string, request, jsonify

app = Flask(__name__)
DB_PATH = "provenance.db"

# DB init
def init_db():
    if os.path.exists(DB_PATH):
        return
    sql = open("schema_sqlite.sql").read()
    conn = sqlite3.connect(DB_PATH)
    conn.executescript(sql)
    conn.commit()
    conn.close()

def get_conn():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn

def run_query(sql, params=None):
    with get_conn() as conn:
        cur = conn.execute(sql, params or [])
        cols = [d[0].lower() for d in cur.description]
        rows = [dict(r) for r in cur.fetchall()]
    return cols, rows

#Provenance queries
PROV_QUERIES = {
    "why_order_total": {
        "label": "Why is Order 1 total 1549.99?",
        "desc": "Why-Provenance: Shows each product contributing to Order 1's total",
        "sql": """SELECT oi.product_id, p.name, oi.quantity, oi.unit_price,
                         ROUND(oi.quantity * oi.unit_price, 2) AS line_total
                  FROM order_items oi JOIN products p ON p.product_id = oi.product_id
                  WHERE oi.order_id = 1"""
    },
    "where_laptop_price": {
        "label": "How did Laptop price change?",
        "desc": "Where-Provenance: Full price history of Laptop from audit log",
        "sql": """SELECT ap.operation_time, ap.operation, ap.old_price, ap.new_price, ap.actor
                  FROM audit_products ap JOIN products p ON p.product_id = ap.product_id
                  WHERE p.name = 'Laptop' ORDER BY ap.operation_time"""
    },
    "how_order_status": {
        "label": "How did Order 1 status evolve?",
        "desc": "How-Provenance: Full lifecycle of Order 1 (CREATED to PAID to SHIPPED)",
        "sql": """SELECT operation_time, operation, old_status, new_status, actor
                  FROM audit_orders WHERE order_id = 1 ORDER BY operation_time"""
    },
    "where_user_actions": {
        "label": "What did app_user do on Orders?",
        "desc": "Where-Provenance: All order operations by current actor",
        "sql": """SELECT actor, operation, order_id, operation_time, old_status, new_status
                  FROM audit_orders WHERE actor = 'app_user' ORDER BY operation_time"""
    },
    "why_headphones_qty": {
        "label": "Why are there 3 Headphones in Order 1?",
        "desc": "Why-Provenance: Quantity change trail for Headphones in Order 1",
        "sql": """SELECT operation_time, operation, old_quantity, new_quantity, actor
                  FROM audit_order_items WHERE order_id=1 AND product_id=3
                  ORDER BY operation_time"""
    },
}

TABLES = [
    "customers","products","orders","order_items","payments",
    "audit_customers","audit_products","audit_orders","audit_order_items","audit_payments"
]

# HTML
HTML = r"""<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Provenance DB Explorer</title>
<style>
  *{box-sizing:border-box;margin:0;padding:0}
  body{font-family:Arial,sans-serif;background:#f0f4f8;color:#222}
  header{background:#1a5276;color:#fff;padding:14px 24px;display:flex;align-items:center;gap:12px}
  header span{font-size:1.15rem;font-weight:bold}
  header small{font-size:.75rem;opacity:.75;margin-left:4px}
  .wrap{max-width:1150px;margin:20px auto;padding:0 16px;display:flex;flex-direction:column;gap:16px}
  .card{background:#fff;border-radius:8px;padding:18px;box-shadow:0 1px 4px rgba(0,0,0,.1)}
  .card h3{font-size:.9rem;color:#1a5276;margin-bottom:12px;text-transform:uppercase;letter-spacing:.5px}
  .row{display:flex;gap:8px;flex-wrap:wrap;align-items:center}
  select,textarea{border:1px solid #ccc;border-radius:4px;padding:6px 10px;font-size:.88rem;background:#fff}
  select{min-width:200px}
  textarea{width:100%;min-height:64px;font-family:monospace;resize:vertical;margin-top:6px}
  .btn{padding:6px 16px;background:#1a5276;color:#fff;border:none;border-radius:4px;cursor:pointer;font-size:.88rem}
  .btn:hover{background:#154360}
  .btn.secondary{background:#aab7b8;color:#222}
  .btn.secondary:hover{background:#909d9e}
  .prov-grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(210px,1fr));gap:8px;margin-top:4px}
  .pq{border:1px solid #aed6f1;border-radius:6px;padding:10px;cursor:pointer;font-size:.8rem;background:#eaf4fb;transition:all .15s}
  .pq:hover,.pq.active{background:#1a5276;color:#fff;border-color:#1a5276}
  .pq .badge{display:inline-block;font-size:.68rem;padding:1px 6px;border-radius:10px;margin-bottom:4px;background:#d6eaf8;color:#1a5276;font-weight:bold}
  .pq.active .badge{background:rgba(255,255,255,.25);color:#fff}
  .pq b{display:block;margin-bottom:3px}
  .result-box{margin-top:12px}
  .desc-bar{font-size:.78rem;color:#555;margin-bottom:8px;padding:6px 10px;background:#fdfefe;border-left:3px solid #1a5276;border-radius:0 4px 4px 0}
  table{width:100%;border-collapse:collapse;font-size:.8rem}
  th{background:#d6eaf8;padding:6px 8px;border:1px solid #aed6f1;text-align:left;white-space:nowrap}
  td{padding:5px 8px;border:1px solid #e8e8e8;word-break:break-word;vertical-align:top}
  tr:nth-child(even){background:#f7fbff}
  .tag-INSERT{color:#1e8449;font-weight:bold}
  .tag-UPDATE{color:#d68910;font-weight:bold}
  .tag-DELETE{color:#c0392b;font-weight:bold}
  .overflow{overflow-x:auto;max-height:360px;overflow-y:auto;border-radius:4px}
  .count{font-size:.75rem;color:#777;margin-top:6px}
  .err{color:#c0392b;font-size:.85rem;margin-top:8px}
  .empty{color:#888;font-size:.85rem;margin-top:8px}
  .spinner{display:none;font-size:.8rem;color:#888;margin-top:8px}
  .spinner.show{display:block}
</style>
</head>
<body>
<header>
  <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
    <ellipse cx="12" cy="5" rx="9" ry="3"/><path d="M3 5v14a9 3 0 0018 0V5"/><path d="M3 12a9 3 0 0018 0"/>
  </svg>
  <span>Provenance-Enabled Relational Database for E-Commerce</span>

</header>

<div class="wrap">

  <div class="card">
    <h3>Browse Table</h3>
    <div class="row">
      <select id="tbl-select">
        <option value="">-- select table --</option>
        {% for t in tables %}<option>{{t}}</option>{% endfor %}
      </select>
      <button class="btn" onclick="loadTable()">Load</button>
    </div>
    <div class="spinner" id="tbl-spin">Loading...</div>
    <div class="result-box" id="tbl-result"></div>
  </div>

  <div class="card">
    <h3>Provenance Queries</h3>
    <div class="prov-grid">
      {% for k,v in queries.items() %}
      <div class="pq" id="pq-{{k}}" onclick="runProv('{{k}}')">
        <b>{{v.label}}</b>
      </div>
      {% endfor %}
    </div>
    <div class="spinner" id="prov-spin">Loading...</div>
    <div class="result-box" id="prov-result"></div>
  </div>

  <div class="card">
    <h3>Custom SQL <span style="font-weight:normal;color:#888;font-size:.78rem">(SELECT only)</span></h3>
    <textarea id="sql-box" placeholder="SELECT * FROM audit_orders ORDER BY operation_time"></textarea>
    <div class="row" style="margin-top:8px">
      <button class="btn" onclick="runCustom()">Run</button>
      <button class="btn secondary" onclick="document.getElementById('sql-box').value=''">Clear</button>
    </div>
    <div class="spinner" id="custom-spin">Loading...</div>
    <div class="result-box" id="custom-result"></div>
  </div>

</div>
<script>
const DESCS = QUERIES_JSON_PLACEHOLDER;

async function post(url,body){
  const r=await fetch(url,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(body)});
  return r.json();
}
function renderTable(data,tid,desc){
  const el=document.getElementById(tid);
  if(data.error){el.innerHTML='<p class="err">'+data.error+'</p>';return;}
  if(!data.rows||!data.rows.length){el.innerHTML='<p class="empty">No rows returned.</p>';return;}
  let h='';
  if(desc)h+='<div class="desc-bar">'+desc+'</div>';
  h+='<div class="overflow"><table><thead><tr>';
  data.cols.forEach(c=>h+='<th>'+c+'</th>');
  h+='</tr></thead><tbody>';
  data.rows.forEach(r=>{
    h+='<tr>';
    data.cols.forEach(c=>{
      const v=r[c]??'';
      const cls=(c==='operation'&&['INSERT','UPDATE','DELETE'].includes(String(v)))?'tag-'+v:'';
      h+='<td'+(cls?' class="'+cls+'"':'')+'>'+v+'</td>';
    });
    h+='</tr>';
  });
  h+='</tbody></table></div><p class="count">'+data.rows.length+' row(s)</p>';
  el.innerHTML=h;
}
function spin(id,s){document.getElementById(id).className='spinner'+(s?' show':'');}
async function loadTable(){
  const t=document.getElementById('tbl-select').value;if(!t)return;
  document.getElementById('tbl-result').innerHTML='';spin('tbl-spin',true);
  const d=await post('/api/table',{table:t});spin('tbl-spin',false);
  renderTable(d,'tbl-result');
}
async function runProv(key){
  document.querySelectorAll('.pq').forEach(e=>e.classList.remove('active'));
  document.getElementById('pq-'+key).classList.add('active');
  document.getElementById('prov-result').innerHTML='';spin('prov-spin',true);
  const d=await post('/api/prov',{key:key});spin('prov-spin',false);
  renderTable(d,'prov-result',DESCS[key]||'');
}
async function runCustom(){
  const sql=document.getElementById('sql-box').value.trim();if(!sql)return;
  document.getElementById('custom-result').innerHTML='';spin('custom-spin',true);
  const d=await post('/api/custom',{sql:sql});spin('custom-spin',false);
  renderTable(d,'custom-result');
}
</script>
</body>
</html>"""


@app.route("/")
def index():
    descs = {k: v["desc"] for k, v in PROV_QUERIES.items()}
    html = HTML.replace("QUERIES_JSON_PLACEHOLDER", json.dumps(descs))
    return render_template_string(html, tables=TABLES, queries=PROV_QUERIES)

@app.route("/api/table", methods=["POST"])
def api_table():
    tbl = request.json.get("table","").lower()
    if tbl not in TABLES:
        return jsonify({"error":"Invalid table"})
    try:
        cols, rows = run_query(f"SELECT * FROM {tbl} LIMIT 200")
        return jsonify({"cols":cols,"rows":rows})
    except Exception as e:
        return jsonify({"error":str(e)})

@app.route("/api/prov", methods=["POST"])
def api_prov():
    key = request.json.get("key","")
    q = PROV_QUERIES.get(key)
    if not q:
        return jsonify({"error":"Unknown query"})
    try:
        cols, rows = run_query(q["sql"])
        return jsonify({"cols":cols,"rows":rows})
    except Exception as e:
        return jsonify({"error":str(e)})

@app.route("/api/custom", methods=["POST"])
def api_custom():
    sql = request.json.get("sql","").strip()
    if not sql.upper().startswith("SELECT"):
        return jsonify({"error":"Only SELECT statements allowed"})
    try:
        cols, rows = run_query(sql)
        return jsonify({"cols":cols,"rows":rows})
    except Exception as e:
        return jsonify({"error":str(e)})

if __name__ == "__main__":
    init_db()
    print("\n DB ready. Open http://localhost:5000\n")
    app.run(debug=True, port=5000)