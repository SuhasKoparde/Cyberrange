"""
Script to add the `execution_steps` column to the `challenge` table if it does not exist.
Run with: `python scripts/add_execution_steps_column.py` from repo root (venv activated).
"""
import sqlite3
import os

repo_root = os.path.dirname(os.path.dirname(__file__))
candidate_paths = [
    os.path.join(repo_root, 'cyber_range.db'),
    os.path.join(repo_root, 'instance', 'cyber_range.db'),
]

DB_PATH = None
for p in candidate_paths:
    if os.path.exists(p):
        DB_PATH = p
        break

if not DB_PATH:
    print('Database not found in repo root or instance/ folder.')
    print('Checked paths:')
    for p in candidate_paths:
        print(' -', p)
    raise SystemExit(1)

conn = sqlite3.connect(DB_PATH)
cursor = conn.cursor()
try:
    cursor.execute("PRAGMA table_info('challenge')")
    columns = [row[1] for row in cursor.fetchall()]
    if 'execution_steps' in columns:
        print('Column execution_steps already exists.')
    else:
        print('Adding execution_steps column to challenge table...')
        cursor.execute('ALTER TABLE challenge ADD COLUMN execution_steps TEXT')
        conn.commit()
        print('Column added successfully.')
except Exception as e:
    print('Error while adding column:', e)
finally:
    conn.close()
