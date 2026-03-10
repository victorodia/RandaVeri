from database import SessionLocal, Organisation, User, Wallet, Transaction, AdminRole
import os

def verify():
    db = SessionLocal()
    try:
        org_count = db.query(Organisation).count()
        user_count = db.query(User).count()
        wallet_count = db.query(Wallet).count()
        transaction_count = db.query(Transaction).count()
        role_count = db.query(AdminRole).count()
        
        admins = db.query(User).filter(User.role.like('%admin%'), User.organisation_id == None).all()
        admin_usernames = [a.username for a in admins]

        print(f"Organizations: {org_count}")
        print(f"Users: {user_count}")
        print(f"Wallets: {wallet_count}")
        print(f"Transactions: {transaction_count}")
        print(f"Admin Roles: {role_count}")
        print(f"Remaining Admins: {admin_usernames}")

        success = (org_count == 0 and wallet_count == 0 and transaction_count == 0 and len(admins) == user_count)
        if success:
            print("Cleanup VERIFIED: Only platform administrators remain.")
        else:
            print("Cleanup VERIFICATION FAILED: Some unexpected data remains.")

    finally:
        db.close()

if __name__ == "__main__":
    verify()
