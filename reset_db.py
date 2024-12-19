import os
from app import db, app

if os.path.exists('messages.db'):
    os.remove('messages.db')
    print("Старая база данных удалена")

with app.app_context():
    db.create_all()
    print("Создана новая база данных")
