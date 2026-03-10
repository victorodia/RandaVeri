from database import SessionLocal, Organisation, User, Wallet, Transaction, AdminRole, ActivityLog, PasswordResetToken, EmailVerificationToken, RevokedToken
import os
import shutil

def cleanup():
    db = SessionLocal()
    try:
        print("Starting data cleanup...")

        # 1. Identify platform admins to preserve
        # Assuming platform admins have role='admin' and usually no organisation_id or belong to a system org
        admins = db.query(User).filter(User.role.like('%admin%'), User.organisation_id == None).all()
        admin_ids = [admin.id for admin in admins]
        print(f"Found {len(admin_ids)} platform administrators to preserve: {[a.username for a in admins]}")

        # 2. Delete data from secondary tables first (due to potential FKs, though many are relaxed)
        print("Clearing transactions...")
        db.query(Transaction).delete()

        print("Clearing wallets...")
        db.query(Wallet).delete()

        print("Clearing activity logs...")
        db.query(ActivityLog).delete()

        print("Clearing password reset tokens...")
        db.query(PasswordResetToken).delete()

        print("Clearing email verification tokens...")
        db.query(EmailVerificationToken).delete()

        print("Clearing revoked tokens...")
        db.query(RevokedToken).delete()

        print("Clearing admin roles...")
        db.query(AdminRole).delete()

        # 3. Delete non-admin users
        print("Clearing non-platform-admin users...")
        db.query(User).filter(~User.id.in_(admin_ids)).delete(synchronize_session=False)

        # 4. Delete organisations
        print("Clearing organisations...")
        db.query(Organisation).delete()

        db.commit()
        print("Database cleanup COMPLETED successfully.")

        # 5. Clear uploads directory
        upload_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "uploads")
        if os.path.exists(upload_dir):
            print(f"Clearing uploads directory: {upload_dir}")
            for filename in os.listdir(upload_dir):
                file_path = os.path.join(upload_dir, filename)
                try:
                    if os.path.isfile(file_path) or os.path.islink(file_path):
                        os.unlink(file_path)
                    elif os.path.isdir(file_path):
                        shutil.rmtree(file_path)
                except Exception as e:
                    print(f'Failed to delete {file_path}. Reason: {e}')
            print("Uploads directory cleared.")

    except Exception as e:
        db.rollback()
        print(f"Cleanup FAILED: {e}")
    finally:
        db.close()

if __name__ == "__main__":
    cleanup()
