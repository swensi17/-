import asyncio
import os
from datetime import datetime
from telethon import TelegramClient
from telethon.sessions import StringSession
from app import db, Message, MessageLog
from dotenv import load_dotenv

load_dotenv()

async def send_message(client, target, text):
    try:
        await client.send_message(target.strip(), text)
        return True, None
    except Exception as e:
        return False, str(e)

async def process_message(message):
    try:
        user = message.user
        if not user or not user.session_string:
            message.status = 'failed'
            message.error_count += 1
            db.session.commit()
            return

        client = TelegramClient(
            StringSession(user.session_string),
            os.getenv('API_ID'),
            os.getenv('API_HASH')
        )

        await client.connect()
        if not await client.is_user_authorized():
            message.status = 'failed'
            message.error_count += 1
            db.session.commit()
            return

        targets = [t.strip() for t in message.targets.split(',') if t.strip()]
        message.status = 'running'
        db.session.commit()

        for _ in range(message.repeat_count):
            for target in targets:
                success, error = await send_message(client, target, message.text)
                
                log = MessageLog(
                    message_id=message.id,
                    target=target,
                    status='success' if success else 'error',
                    error_message=error
                )
                db.session.add(log)
                
                if success:
                    message.sent_count += 1
                else:
                    message.error_count += 1
                db.session.commit()

                if message.interval > 0:
                    await asyncio.sleep(message.interval)

        message.status = 'completed'
        db.session.commit()

    except Exception as e:
        message.status = 'failed'
        message.error_count += 1
        db.session.commit()
    finally:
        await client.disconnect()

async def scheduler():
    while True:
        try:
            # Находим все сообщения, которые нужно отправить
            current_time = datetime.utcnow()
            pending_messages = Message.query.filter(
                Message.status == 'pending',
                Message.start_time <= current_time
            ).all()

            # Обрабатываем каждое сообщение
            for message in pending_messages:
                asyncio.create_task(process_message(message))

            # Ждем 10 секунд перед следующей проверкой
            await asyncio.sleep(10)

        except Exception as e:
            print(f"Ошибка в планировщике: {e}")
            await asyncio.sleep(10)

if __name__ == '__main__':
    loop = asyncio.get_event_loop()
    try:
        loop.run_until_complete(scheduler())
    except KeyboardInterrupt:
        pass
    finally:
        loop.close()
