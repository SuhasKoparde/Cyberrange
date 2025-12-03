"""
Backfill `execution_steps` for existing challenges by deriving from `how_to_execute`.
Run with: `python scripts/backfill_execution_steps.py` from repo root (venv activated).
"""
from app import app, db, Challenge
import json

with app.app_context():
    challenges = Challenge.query.all()
    updated = 0
    for c in challenges:
        if not c.execution_steps:
            raw = c.how_to_execute or ''
            steps = [line.strip() for line in raw.split('\n') if line.strip()]
            if steps:
                c.execution_steps = json.dumps(steps)
                updated += 1
    if updated:
        db.session.commit()
    print(f'Backfilled execution_steps for {updated} challenges.')
