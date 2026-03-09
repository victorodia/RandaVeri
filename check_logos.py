
import sys
import os
sys.path.append(os.path.join(os.getcwd(), 'backend'))

from backend.database import SessionLocal, Organisation

db = SessionLocal()
orgs = db.query(Organisation).all()

print(f"{'ID':<5} | {'Slug':<15} | {'Logo URL'}")
print("-" * 60)
for org in orgs:
    print(f"{org.id:<5} | {org.slug:<15} | {org.logo_url}")
db.close()
