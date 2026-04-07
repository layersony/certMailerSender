from models import db, User

email = input("Enter the email of the user to activate: ").strip()
role = input("Enter the Role: ").strip()
user = User.query.filter_by(email=email).first()
if user:
    user.status = "active"
    user.role = role
    db.session.commit()
    print(f"{email} is now active and Admin")
else:
    print(f"User {email} not found")