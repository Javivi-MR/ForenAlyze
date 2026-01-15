from werkzeug.security import generate_password_hash
from app import create_app
from app.extensions import db
from app.models import User

app = create_app()

with app.app_context():
    db.create_all()
    if not User.query.filter_by(username='admin').first():
        user = User(
            username='admin',
            password=generate_password_hash('admin123'),
            image_url=None,
            notifications=0
        )
        db.session.add(user)
        db.session.commit()
        print('Usuario admin creado (admin/admin123)')
    else:
        print('Usuario admin ya existe')
