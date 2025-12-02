from datetime import datetime, timedelta
from models import db, DataRetentionPolicy

def retention_job(now=None):
    """Example retention sweep. Implement selects per category/table."""
    now = now or datetime.utcnow()
    # TODO: For each policy, locate records older than now - retention_days and delete/anonimize.
    # Keep as placeholder so you can wire specific tables later (certificados, logs etc.).
    return {"ok": True, "ran_at": str(now)}
