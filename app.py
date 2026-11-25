from flask import Flask, render_template, request, jsonify
import sqlite3, re, json, random
from datetime import datetime, timedelta
from pathlib import Path

app = Flask(__name__)
DB = Path(__file__).with_name('bankshield.db')

EMPLOYEES = [
    ('EMP-101','Aarav Mehta','Operations','Analyst'), ('EMP-102','Isha Sharma','Finance','Analyst'),
    ('EMP-103','Kabir Singh','Customer Support','Associate'), ('EMP-104','Riya Kapoor','IT Security','Admin'),
    ('EMP-105','Dev Patel','Retail Banking','Associate'), ('EMP-106','Ananya Rao','Risk','Analyst')]

def db():
    c=sqlite3.connect(DB); c.row_factory=sqlite3.Row; return c

def init_db():
    with db() as c:
        c.executescript('''CREATE TABLE IF NOT EXISTS activities(id INTEGER PRIMARY KEY AUTOINCREMENT, ts TEXT, employee_id TEXT, employee TEXT, department TEXT, action TEXT, records INTEGER, risk INTEGER, level TEXT, status TEXT, reason TEXT);
        CREATE TABLE IF NOT EXISTS incidents(id INTEGER PRIMARY KEY AUTOINCREMENT, ts TEXT, employee TEXT, type TEXT, risk INTEGER, level TEXT, status TEXT, details TEXT, response TEXT);''')
        if c.execute('SELECT COUNT(*) FROM activities').fetchone()[0]==0:
            now=datetime.now()
            seed=[('EMP-101','Aarav Mehta','Operations','Viewed customer profile',3,12,'LOW','Allowed','Routine access within role'),('EMP-102','Isha Sharma','Finance','Statement lookup',8,22,'LOW','Allowed','Small record volume'),('EMP-103','Kabir Singh','Customer Support','Customer verification',5,28,'MEDIUM','Warning','Sensitive fields accessed'),('EMP-104','Riya Kapoor','IT Security','Audit log review',24,18,'LOW','Allowed','Authorized security review'),('EMP-105','Dev Patel','Retail Banking','Account search',12,34,'MEDIUM','Flagged','Above typical access volume')]
            for i,row in enumerate(seed):
                c.execute('INSERT INTO activities(ts,employee_id,employee,department,action,records,risk,level,status,reason) VALUES(?,?,?,?,?,?,?,?,?,?)',((now-timedelta(minutes=i*7)).strftime('%Y-%m-%d %H:%M:%S'),*row))

def risk_score(records=1, sensitive=False, off_hours=False, repeated=False, unusual=False, export=False):
    score=0; reasons=[]
    if records>=1000: score+=30; reasons.append('Bulk data access (+30)')
    elif records>=100: score+=15; reasons.append('Elevated record volume (+15)')
    if sensitive: score+=20; reasons.append('Sensitive data access (+20)')
    if off_hours: score+=15; reasons.append('Outside business hours (+15)')
    if repeated: score+=15; reasons.append('Repeated access pattern (+15)')
    if unusual: score+=15; reasons.append('Unusual session/location (+15)')
    if export: score+=25; reasons.append('Export attempt (+25)')
    score=min(score,100)
    level='LOW' if score<25 else 'MEDIUM' if score<50 else 'HIGH' if score<75 else 'CRITICAL'
    status='Allowed' if level=='LOW' else 'Warning' if level=='MEDIUM' else 'Flagged' if level=='HIGH' else 'Blocked (simulation)'
    return score,level,status,reasons

@app.route('/')
def index(): return render_template('index.html')
@app.route('/api/data')
def data():
    with db() as c:
        activities=[dict(r) for r in c.execute('SELECT * FROM activities ORDER BY id DESC LIMIT 60')]
        incidents=[dict(r) for r in c.execute('SELECT * FROM incidents ORDER BY id DESC LIMIT 40')]
    counts={'activities':len(activities),'threats':sum(1 for a in activities if a['risk']>=50),'blocked':sum(1 for a in activities if 'Blocked' in a['status']),'employees':len(EMPLOYEES)}
    return jsonify({'activities':activities,'incidents':incidents,'counts':counts,'employees':[{'id':e[0],'name':e[1],'department':e[2],'role':e[3]} for e in EMPLOYEES]})
@app.route('/api/simulate',methods=['POST'])
def simulate():
    s=request.json.get('scenario','normal'); now=datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    mapping={
      'normal':dict(emp=0,action='Routine customer profile lookup',records=5,sensitive=False,off_hours=False,repeated=False,unusual=False,export=False,kind='Normal activity'),
      'bulk':dict(emp=4,action='Bulk customer data export attempt',records=5000,sensitive=True,off_hours=False,repeated=True,unusual=True,export=True,kind='Bulk data extraction'),
      'insider':dict(emp=2,action='Repeated sensitive customer record access',records=240,sensitive=True,off_hours=False,repeated=True,unusual=True,export=False,kind='Insider threat pattern'),
      'login':dict(emp=5,action='Login from unusual location at 02:14',records=18,sensitive=True,off_hours=True,repeated=False,unusual=True,export=False,kind='Suspicious login')}
    if s not in mapping:return jsonify({'error':'Unknown simulation'}),400
    m=mapping[s]; emp=EMPLOYEES[m['emp']]; score,level,status,reasons=risk_score(**{k:m[k] for k in ['records','sensitive','off_hours','repeated','unusual','export']})
    if not reasons: reasons=['Normal access volume and expected activity pattern']
    with db() as c:
      c.execute('INSERT INTO activities(ts,employee_id,employee,department,action,records,risk,level,status,reason) VALUES(?,?,?,?,?,?,?,?,?,?)',(now,emp[0],emp[1],emp[2],m['action'],m['records'],score,level,status,'; '.join(reasons)))
      if score>=50:
        response='Simulated export block and session suspension' if score>=75 else 'Activity flagged for analyst review'
        c.execute('INSERT INTO incidents(ts,employee,type,risk,level,status,details,response) VALUES(?,?,?,?,?,?,?,?)',(now,emp[1],m['kind'],score,level,'Open',m['action']+' | '+ '; '.join(reasons),response))
    return jsonify({'employee':emp[1],'employee_id':emp[0],'action':m['action'],'records':m['records'],'risk':score,'level':level,'status':status,'reasons':reasons,'response':'Simulated export blocked and session suspended' if score>=75 else 'Flagged for security review' if score>=50 else 'Activity allowed','timestamp':now,'scenario':m['kind']})
@app.route('/api/dlp',methods=['POST'])
def dlp():
    text=request.json.get('text','')
    patterns=[('Email',r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b','MEDIUM'),('Phone',r'\b(?:\+91[- ]?)?[6-9]\d{9}\b','MEDIUM'),('PAN-like ID',r'\b[A-Z]{5}[0-9]{4}[A-Z]\b','HIGH'),('Aadhaar-like ID',r'\b\d{4}[ -]?\d{4}[ -]?\d{4}\b','HIGH'),('Account number',r'\b(?:AC|ACC|ACCOUNT)[- ]?\d{8,14}\b','HIGH'),('Password-like',r'(?i)\b(password|passwd|pwd)\s*[:=]\s*[^\s,;]+','CRITICAL')]
    found=[]
    for label,pat,severity in patterns:
      for m in re.finditer(pat,text):
        raw=m.group(0); masked=raw[:2]+'•'*max(4,len(raw)-4)+raw[-2:] if len(raw)>4 else '••••'
        found.append({'type':label,'severity':severity,'masked':masked,'start':m.start()})
    return jsonify({'scanned_chars':len(text),'detections':found,'count':len(found),'safe':len(found)==0})
@app.route('/api/incidents/<int:iid>/resolve',methods=['POST'])
def resolve(iid):
    with db() as c: c.execute("UPDATE incidents SET status='Resolved' WHERE id=?",(iid,))
    return jsonify({'ok':True})
@app.route('/api/reset',methods=['POST'])
def reset():
    with db() as c: c.execute('DELETE FROM activities'); c.execute('DELETE FROM incidents'); c.execute('DELETE FROM sqlite_sequence WHERE name IN (\'activities\',\'incidents\')')
    init_db(); return jsonify({'ok':True})
init_db()
if __name__=='__main__': app.run(debug=True,port=5000)
