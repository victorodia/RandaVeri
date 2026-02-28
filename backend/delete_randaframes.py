from database import SessionLocal, Organisation
db = SessionLocal()
try:
    org = db.query(Organisation).filter(Organisation.name == 'Randaframes').first()
    if org:
        org.is_deleted = True
        db.commit()
        print(f"Soft deleted: {org.name}")
    else:
        print("Organisation 'Randaframes' not found.")
finally:
    db.close()
