import sqlite3
import json

db_path = 'cyber_range.db'
conn = sqlite3.connect(db_path)
cur = conn.cursor()

rows = cur.execute('SELECT id, name, how_to_execute, execution_steps FROM challenge ORDER BY id').fetchall()
print(f'Total challenges: {len(rows)}')
for r in rows:
    cid, name, how_text, exec_raw = r
    has_exec = bool(exec_raw)
    count = 0
    sample = None
    if has_exec:
        try:
            parsed = json.loads(exec_raw)
            if isinstance(parsed, list):
                count = len(parsed)
                sample = parsed[:3]
            else:
                sample = parsed
        except Exception as e:
            sample = f'PARSE_ERROR: {e}'
    else:
        if how_text:
            lines = [l.strip() for l in how_text.split('\n') if l.strip()]
            count = len(lines)
            sample = lines[:3]
    print(f'ID={cid} | Name={name} | has_exec={has_exec} | steps_count={count} | sample={sample}')

conn.close()
