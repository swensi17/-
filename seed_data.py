from app import app, db, User, Message, MessageLog
from datetime import datetime, timedelta, timezone
import random

def seed_database():
    with app.app_context():
        # Очищаем базу данных
        db.drop_all()
        db.create_all()
        
        # Создаем тестового пользователя
        user = User(
            phone='+79123456789',
            session_string='test_session_string',
            last_login=datetime.now(timezone.utc),
            created_at=datetime.now(timezone.utc)
        )
        db.session.add(user)
        db.session.commit()
        
        # Создаем тестовые сообщения
        statuses = ['completed', 'pending', 'running', 'error']
        for i in range(10):
            message = Message(
                text=f'Тестовое сообщение {i + 1}',
                targets='["123456789", "987654321"]',
                interval=random.randint(0, 60),
                repeat_count=random.randint(1, 5),
                start_time=datetime.now(timezone.utc) - timedelta(days=random.randint(0, 7)),
                status=random.choice(statuses),
                sent_count=random.randint(0, 10),
                total_count=10,
                error_count=random.randint(0, 3),
                created_at=datetime.now(timezone.utc) - timedelta(days=random.randint(0, 7)),
                user_id=user.id
            )
            db.session.add(message)
            
            # Создаем логи для каждого сообщения
            for _ in range(random.randint(3, 8)):
                log = MessageLog(
                    message_id=message.id,
                    target=str(random.randint(100000000, 999999999)),
                    status=random.choice(['success', 'error']),
                    error_message='Тестовая ошибка' if random.random() < 0.2 else None,
                    sent_at=datetime.now(timezone.utc) - timedelta(hours=random.randint(0, 24))
                )
                db.session.add(log)
        
        db.session.commit()
        print("База данных заполнена тестовыми данными!")

if __name__ == '__main__':
    seed_database()
