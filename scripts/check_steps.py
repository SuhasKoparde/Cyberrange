from app import app, db, Challenge
import json

with app.app_context():
    challenges = Challenge.query.order_by(Challenge.id).all()
    print(f"Total challenges: {len(challenges)}")
    for c in challenges:
        exec_raw = c.execution_steps
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
                sample = f"PARSE_ERROR: {e}"
        else:
            # fallback to how_to_execute split
            if c.how_to_execute:
                lines = [l.strip() for l in c.how_to_execute.split('\n') if l.strip()]
                count = len(lines)
                sample = lines[:3]

        print(f"ID={c.id} | Name={c.name} | has_exec={has_exec} | steps_count={count} | sample={sample}")
