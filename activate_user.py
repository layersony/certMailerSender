from models import db, User

email = input("Enter the email of the user to activate: ").strip()
user = User.query.filter_by(email=email).first()
if user:
    user.status = "active"
    db.session.commit()
    print(f"{email} is now active")
else:
    print(f"User {email} not found")