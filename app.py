from flask import Flask, render_template, request, jsonify, session, redirect
from telethon import TelegramClient
from telethon.sessions import StringSession, MemorySession
from telethon.tl.functions.messages import GetDialogsRequest
import os
from dotenv import load_dotenv
from flask_sqlalchemy import SQLAlchemy
import asyncio
import nest_asyncio
import sys
import platform
import pickle
import base64
import contextlib
from datetime import datetime, timedelta, timezone
import logging
import secrets
import re
from telethon.errors import PhoneCodeExpiredError, PhoneCodeInvalidError, SessionPasswordNeededError, FloodWaitError, PhoneNumberBannedError, PhoneNumberInvalidError
import pytz

nest_asyncio.apply()

load_dotenv()

app = Flask(__name__)
# Генерируем случайный ключ при запуске
app.secret_key = os.getenv('SECRET_KEY', secrets.token_hex(32))
# Настраиваем сессию
app.config.update(
    SESSION_COOKIE_SECURE=False,  # Для разработки используем False
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE='Lax',
    PERMANENT_SESSION_LIFETIME=timedelta(days=7),  # Сессия живет 7 дней
)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///messages.db'
db = SQLAlchemy(app)

# Параметры для Telethon
DEVICE_MODEL = "Windows Desktop"
SYSTEM_VERSION = platform.version()
APP_VERSION = "1.0.0"
LANG_CODE = 'ru'
SYSTEM_LANG_CODE = 'ru'

# Настройка логирования
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    phone = db.Column(db.String(20), unique=True)
    session_string = db.Column(db.Text)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    last_login = db.Column(db.DateTime)

class Message(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    text = db.Column(db.Text)
    targets = db.Column(db.Text)
    interval = db.Column(db.Integer, default=0)  # Интервал в секундах
    repeat_count = db.Column(db.Integer, default=1)  # Количество повторов
    start_time = db.Column(db.DateTime)  # Время начала рассылки
    status = db.Column(db.String(20), default='pending')  # pending, running, completed, failed
    sent_count = db.Column(db.Integer, default=0)  # Количество успешных отправок
    total_count = db.Column(db.Integer, default=0)  # Общее количество отправок
    error_count = db.Column(db.Integer, default=0)  # Количество ошибок
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))

class MessageLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    message_id = db.Column(db.Integer, db.ForeignKey('message.id'))
    target = db.Column(db.String(100))
    status = db.Column(db.String(20))  # success, error
    error_message = db.Column(db.Text)
    sent_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))

class TempAuth(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    phone = db.Column(db.String(20), unique=True)
    phone_code_hash = db.Column(db.String(100))
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))

    @classmethod
    def create_or_update(cls, phone, phone_code_hash):
        auth = cls.query.filter_by(phone=phone).first()
        if auth:
            auth.phone_code_hash = phone_code_hash
            auth.created_at = datetime.now(timezone.utc)
        else:
            auth = cls(phone=phone, phone_code_hash=phone_code_hash)
            db.session.add(auth)
        db.session.commit()
        return auth

    @classmethod
    def get_hash(cls, phone):
        auth = cls.query.filter_by(phone=phone).first()
        if auth and (datetime.now(timezone.utc) - auth.created_at) < timedelta(minutes=30):
            return auth.phone_code_hash
        return None

def create_tables():
    """Создает все таблицы в базе данных"""
    with app.app_context():
        db.create_all()

def init_db():
    """Инициализирует базу данных"""
    create_tables()
    
    # Создаем таблицы если их нет
    if not os.path.exists('instance'):
        os.makedirs('instance')

init_db()

@contextlib.contextmanager
def get_event_loop():
    try:
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        yield loop
    finally:
        try:
            loop.stop()
            loop.close()
        except:
            pass

def run_async(coro):
    """Helper function to run async code in Flask"""
    with get_event_loop() as loop:
        return loop.run_until_complete(coro)

async def create_client():
    """Create and return a Telegram client instance"""
    try:
        client = TelegramClient(StringSession(), os.getenv('API_ID'), os.getenv('API_HASH'), 
                              timeout=300, connection_retries=10)  # увеличиваем timeout до 5 минут
        await client.connect()
        return client
    except Exception as e:
        app.logger.error(f'Error creating client: {str(e)}')
        raise

@app.before_request
def before_request():
    # Делаем сессию постоянной
    session.permanent = True
    
    # Список маршрутов, не требующих авторизации
    public_routes = ['/', '/login', '/verify_code', '/verify', '/resend_code', '/check_auth', '/static']
    
    # Проверяем, нужна ли авторизация для текущего маршрута
    if not any(request.path.startswith(route) for route in public_routes):
        if 'session_string' not in session:
            # Если маршрут требует авторизации, но пользователь не авторизован
            if request.is_xhr:
                return jsonify({'error': 'Unauthorized', 'redirect': '/'}), 401
            return redirect('/')
    
    app.logger.debug('Current session data: %s', dict(session))

@app.route('/')
def index():
    # Проверяем авторизацию при загрузке страницы
    if 'phone' in session:
        user = User.query.filter_by(phone=session['phone']).first()
        if user and user.session_string:
            session['session_string'] = user.session_string
    return render_template('index.html')

@app.route('/login', methods=['POST'])
async def login():
    try:
        data = request.get_json()
        phone = data.get('phone', '')
        
        # Clean the phone number format - keep only digits and plus sign at start
        phone = re.sub(r'[^0-9+]', '', phone)
        if not phone.startswith('+'):
            phone = '+' + phone
            
        app.logger.info(f"Attempting login for phone: {phone}")
        app.logger.info(f"Using API_ID: {os.getenv('API_ID')} and API_HASH: {os.getenv('API_HASH')}")
        
        if not os.getenv('API_ID') or not os.getenv('API_HASH'):
            app.logger.error("API_ID or API_HASH not found in environment variables")
            return jsonify({'error': 'API credentials not configured'}), 500
            
        # Create and connect client
        client = TelegramClient(
            MemorySession(),  # Используем MemorySession вместо StringSession
            int(os.getenv('API_ID')),
            os.getenv('API_HASH'),
            device_model="Chrome",
            system_version="Windows",
            app_version="1.0",
            system_lang_code="en",
            lang_code="en"
        )
        
        try:
            app.logger.info("Connecting to Telegram...")
            await client.connect()
            
            app.logger.info("Connected to Telegram successfully")
            
            if not await client.is_user_authorized():
                app.logger.info("User not authorized, sending code request...")
                
                try:
                    # Отправляем код напрямую через API запрос
                    from telethon.tl.functions.auth import SendCodeRequest
                    from telethon.tl.types import CodeSettings
                    
                    app.logger.info("Preparing code request...")
                    
                    # Создаем настройки кода
                    settings = CodeSettings(
                        allow_flashcall=True,
                        current_number=True,
                        allow_app_hash=True,
                        allow_missed_call=True
                    )
                    
                    # Создаем запрос на отправку кода
                    code_request = SendCodeRequest(
                        phone,
                        int(os.getenv('API_ID')),
                        os.getenv('API_HASH'),
                        settings=settings
                    )
                    
                    app.logger.info("Sending code request...")
                    result = await client(code_request)
                    
                    app.logger.info(f"Code request response type: {type(result)}")
                    app.logger.info(f"Code request response: {result}")
                    app.logger.info(f"Phone code hash: {result.phone_code_hash}")
                    app.logger.info(f"Code type: {result.type}")
                    
                    # Store data in session and database
                    session['phone'] = phone
                    session['phone_code_hash'] = result.phone_code_hash
                    
                    # Store in temporary auth
                    TempAuth.create_or_update(phone, result.phone_code_hash)
                    
                    return jsonify({
                        'success': True,
                        'code_type': str(result.type.__class__.__name__),
                        'next_type': getattr(result, 'next_type', None)
                    })
                    
                except Exception as e:
                    app.logger.error(f"Error sending code request: {str(e)}")
                    # Пробуем с SMS
                    try:
                        app.logger.info("Retrying with SMS...")
                        sent = await client.send_code_request(
                            phone,
                            force_sms=True
                        )
                        app.logger.info(f"SMS code request sent successfully, hash: {sent.phone_code_hash}")
                        
                        session['phone'] = phone
                        session['phone_code_hash'] = sent.phone_code_hash
                        TempAuth.create_or_update(phone, sent.phone_code_hash)
                        
                        return jsonify({'success': True, 'method': 'sms'})
                    except Exception as sms_error:
                        app.logger.error(f"Error sending SMS code: {str(sms_error)}")
                        return jsonify({'error': str(sms_error)}), 400
            else:
                app.logger.info("User already authorized")
                return jsonify({'error': 'User already authorized'}), 400
                
        except Exception as e:
            app.logger.error(f"Error during login: {str(e)}")
            return jsonify({'error': str(e)}), 400
        finally:
            if client and client.is_connected():
                await client.disconnect()
                app.logger.info("Disconnected from Telegram")
                
    except Exception as e:
        error_message = str(e)
        app.logger.error(f"Error in login: {error_message}")
        return jsonify({'error': error_message}), 400

@app.route('/verify')
def verify_page():
    # Проверяем, есть ли уже активная сессия
    if 'session_string' in session:
        return redirect('/dashboard')
    
    # Проверяем наличие номера телефона в сессии
    if 'phone' not in session:
        return redirect('/')
        
    return render_template('verify.html')

@app.route('/verify_code', methods=['POST'])
async def verify_code():
    try:
        if 'phone' not in session:
            app.logger.error("No phone in session")
            return jsonify({'error': 'Сессия истекла. Пожалуйста, попробуйте снова.'}), 400

        data = request.get_json()
        code = data.get('code')
        phone = session.get('phone')
        
        # Получаем хэш из временного хранилища
        temp_auth = TempAuth.query.filter_by(phone=phone).first()
        if not temp_auth:
            return jsonify({'error': 'Сессия истекла. Пожалуйста, запросите код снова.'}), 400
            
        # Проверяем, не истек ли код (5 минут)
        now = datetime.now(timezone.utc)
        code_age = now - temp_auth.created_at.replace(tzinfo=timezone.utc)
        if code_age.total_seconds() > 300:  # 5 минут
            app.logger.error("Code expired due to time")
            # Автоматически отправляем новый код
            client = TelegramClient(StringSession(), os.getenv('API_ID'), os.getenv('API_HASH'))
            try:
                await client.connect()
                sent = await client.send_code_request(phone)
                temp_auth.phone_code_hash = sent.phone_code_hash
                temp_auth.created_at = now
                db.session.commit()
                
                return jsonify({
                    'error': 'Код подтверждения истек. Мы отправили новый код.',
                    'code_resent': True
                }), 400
            finally:
                if client and client.is_connected():
                    await client.disconnect()

        phone_code_hash = temp_auth.phone_code_hash

        app.logger.debug(f"Verifying code for phone: {phone}")
        app.logger.debug(f"Code length: {len(code) if code else 'None'}")

        if not code:
            return jsonify({'error': 'Код подтверждения обязателен'}), 400

        app.logger.info(f"Attempting to sign in with code for phone: {phone}")
        
        client = TelegramClient(StringSession(), os.getenv('API_ID'), os.getenv('API_HASH'))
        try:
            await client.connect()
            
            try:
                # Пробуем войти с кодом
                user = await client.sign_in(phone=phone, code=code, phone_code_hash=phone_code_hash)
                
                if not user:
                    return jsonify({'error': 'Не удалось войти. Пожалуйста, попробуйте снова.'}), 400
                
                # Если успешно, сохраняем сессию
                string_session = client.session.save()
                
                # Создаем или обновляем запись пользователя
                user_db = User.query.filter_by(phone=phone).first()
                if user_db:
                    user_db.session_string = string_session
                    user_db.last_login = now
                else:
                    user_db = User(phone=phone, session_string=string_session, last_login=now)
                    db.session.add(user_db)
                
                # Очищаем временную авторизацию
                db.session.delete(temp_auth)
                db.session.commit()
                
                # Очищаем данные сессии
                session.pop('phone', None)
                session.pop('phone_code_hash', None)
                
                # Сохраняем новую сессию
                session['session_string'] = string_session
                session.permanent = True
                
                app.logger.info(f"Successfully logged in user with phone: {phone}")
                return jsonify({
                    'success': True,
                    'redirect': '/dashboard'
                })
                
            except PhoneCodeInvalidError:
                app.logger.error("Invalid phone code")
                return jsonify({'error': 'Неверный код подтверждения. Пожалуйста, проверьте код и попробуйте снова.'}), 400
                
            except SessionPasswordNeededError:
                app.logger.error("2FA required")
                return jsonify({'error': 'Требуется двухфакторная аутентификация. Пожалуйста, отключите ее в настройках Telegram.'}), 400
                
        except Exception as e:
            app.logger.error(f"Error in verify_code: {str(e)}")
            return jsonify({'error': f'Произошла ошибка при проверке кода: {str(e)}'}), 400
            
        finally:
            if client and client.is_connected():
                await client.disconnect()
            
    except Exception as e:
        app.logger.error(f"Error in verify_code: {str(e)}")
        return jsonify({'error': 'Произошла ошибка при проверке кода'}), 400

@app.route('/resend_code', methods=['POST'])
async def resend_code():
    try:
        if 'phone' not in session:
            return jsonify({'error': 'Сессия истекла'}), 400
            
        phone = session['phone']
        app.logger.info(f"Attempting to resend code for phone: {phone}")
        app.logger.info(f"Using API_ID: {os.getenv('API_ID')} and API_HASH: {os.getenv('API_HASH')}")
        
        # Check if code is requested too frequently
        temp_auth = TempAuth.query.filter_by(phone=phone).first()
        if temp_auth and temp_auth.created_at:
            now = datetime.now(timezone.utc)
            time_passed = now - temp_auth.created_at.replace(tzinfo=timezone.utc)
            if time_passed < timedelta(minutes=1):
                wait_seconds = 60 - time_passed.seconds
                app.logger.warning(f"Code request too frequent. Need to wait {wait_seconds} seconds")
                return jsonify({
                    'error': f'Подождите {wait_seconds} секунд перед повторным запросом кода',
                    'wait_time': wait_seconds
                }), 400

        app.logger.info('Creating Telegram client...')
        # Create and connect client
        client = TelegramClient(StringSession(), os.getenv('API_ID'), os.getenv('API_HASH'))
        try:
            app.logger.info('Connecting to Telegram...')
            await client.connect()
            
            # Send new code
            app.logger.info('Sending code request...')
            result = await client.send_code_request(phone)
            app.logger.info(f"Code request sent successfully, hash: {result.phone_code_hash}")
            
            # Update data in session
            session['phone_code_hash'] = result.phone_code_hash
            
            # Update record in DB
            TempAuth.create_or_update(phone, result.phone_code_hash)
            
            return jsonify({'success': True})
            
        except FloodWaitError as e:
            wait_time = int(str(e).split('Wait ')[1].split(' seconds')[0])
            app.logger.warning(f"FloodWaitError: Need to wait {wait_time} seconds")
            return jsonify({
                'error': f'Слишком много попыток. Подождите {wait_time} секунд.',
                'wait_time': wait_time
            }), 400
        except Exception as e:
            app.logger.error(f"Error while sending code: {str(e)}")
            raise
        finally:
            if client and client.is_connected():
                await client.disconnect()
                app.logger.info('Disconnected from Telegram')
            
    except Exception as e:
        app.logger.error(f"Error in resend_code: {str(e)}")
        return jsonify({'error': 'Произошла ошибка при отправке кода'}), 400

@app.route('/check_session', methods=['GET'])
async def check_session():
    phone = session.get('phone')
    if not phone:
        return jsonify({'authenticated': False}), 401

    user = User.query.filter_by(phone=phone).first()
    if not user or not user.session_string:
        return jsonify({'authenticated': False}), 401

    # Update session from database
    session['session_string'] = user.session_string
    
    try:
        client = await create_client()
        client.session.load(session['session_string'])
        
        try:
            await client.connect()
            if await client.is_user_authorized():
                # Update last login time
                user.last_login = datetime.now(timezone.utc)
                db.session.commit()
                return jsonify({
                    'authenticated': True,
                    'phone': phone
                })
            else:
                # If session is invalid, clear it
                user.session_string = None
                db.session.commit()
                session.clear()
                return jsonify({'authenticated': False}), 401

        finally:
            await client.disconnect()

    except Exception as e:
        return jsonify({'authenticated': False, 'error': str(e)}), 401

@app.route('/schedule_message', methods=['POST'])
async def schedule_message():
    if 'session_string' not in session:
        return jsonify({'error': 'Требуется авторизация'}), 401
        
    try:
        data = request.get_json()
        
        # Check required fields
        required_fields = ['targets', 'text']
        for field in required_fields:
            if not data.get(field):
                return jsonify({'error': f'Поле {field} обязательно'}), 400
        
        # Parse recipients
        targets = [t.strip() for t in data['targets'].split(',')]
        if not targets:
            return jsonify({'error': 'Укажите хотя бы одного получателя'}), 400
            
        # Create new message
        message = Message(
            text=data['text'],
            targets=data['targets'],
            interval=data.get('interval', 0),
            repeat_count=data.get('repeat_count', 1),
            start_time=datetime.fromisoformat(data['start_time']) if data.get('start_time') else datetime.now(timezone.utc),
            status='pending',
            sent_count=0,
            total_count=len(targets) * data.get('repeat_count', 1),
            created_at=datetime.now(timezone.utc)
        )
        
        db.session.add(message)
        db.session.commit()
        
        # Start sending task
        asyncio.create_task(send_messages(message.id))
        
        return jsonify({'success': True, 'message_id': message.id})
        
    except Exception as e:
        app.logger.error(f'Error in schedule_message: {str(e)}')
        return jsonify({'error': 'Ошибка при создании рассылки'}), 400

async def send_messages(message_id):
    """Background task to send messages"""
    try:
        message = Message.query.get(message_id)
        if not message:
            return
            
        message.status = 'running'
        db.session.commit()
        
        client = await create_client()
        client.session.load(session['session_string'])
        
        await client.connect()
        
        targets = [t.strip() for t in message.targets.split(',')]
        
        for _ in range(message.repeat_count):
            for target in targets:
                try:
                    # Try to find recipient
                    entity = await client.get_entity(target)
                    
                    # Send message
                    await client.send_message(entity, message.text)
                    
                    # Update counter
                    message.sent_count += 1
                    db.session.commit()
                    
                    # Wait for specified interval
                    if message.interval > 0:
                        await asyncio.sleep(message.interval)
                        
                except Exception as e:
                    app.logger.error(f'Error sending message to {target}: {str(e)}')
                    continue
                    
        message.status = 'completed'
        db.session.commit()
        
    except Exception as e:
        app.logger.error(f'Error in send_messages task: {str(e)}')
        message.status = 'failed'
        db.session.commit()
        
    finally:
        if 'client' in locals():
            await client.disconnect()

@app.route('/dashboard')
def dashboard():
    if 'session_string' not in session:
        return redirect('/')
        
    try:
        # Get statistics
        stats = {
            'total_messages': Message.query.count(),
            'successful_messages': Message.query.filter_by(status='completed').count(),
            'active_campaigns': Message.query.filter_by(status='running').count(),
            'messages_growth': 0,  # Will be calculated later
            'success_rate': 0,  # Will be calculated later
            'pending_messages': Message.query.filter_by(status='pending').count()
        }
        
        # Calculate success rate
        if stats['total_messages'] > 0:
            stats['success_rate'] = round((stats['successful_messages'] / stats['total_messages']) * 100)
        
        # Get growth over last 7 days
        week_ago = datetime.now(timezone.utc) - timedelta(days=7)
        messages_week_ago = Message.query.filter(Message.created_at <= week_ago).count()
        if messages_week_ago > 0:
            growth = ((stats['total_messages'] - messages_week_ago) / messages_week_ago) * 100
            stats['messages_growth'] = round(growth)
        
        # Get list of messages
        messages = Message.query.order_by(Message.created_at.desc()).all()
        messages_data = []
        
        for msg in messages:
            messages_data.append({
                'text': msg.text,
                'targets': msg.targets,
                'status': msg.status,
                'sent_count': msg.sent_count,
                'total_count': msg.total_count,
                'created_at': msg.created_at
            })
        
        return render_template('dashboard.html', stats=stats, messages=messages_data)
    except Exception as e:
        app.logger.error(f"Error in dashboard: {str(e)}")
        return redirect('/')

@app.route('/logout')
def logout():
    session.clear()
    return redirect('/')

@app.route('/get_messages', methods=['GET'])
def get_messages():
    if 'session_string' not in session:
        return jsonify({'error': 'Необходима авторизация'}), 401

    user = User.query.filter_by(phone=session.get('phone')).first()
    if not user:
        return jsonify({'error': 'Пользователь не найден'}), 404

    messages = Message.query.filter_by(user_id=user.id).order_by(Message.created_at.desc()).all()
    return jsonify([{
        'id': m.id,
        'text': m.text,
        'targets': m.targets,
        'interval': m.interval,
        'repeat_count': m.repeat_count,
        'start_time': m.start_time.isoformat() if m.start_time else None,
        'status': m.status,
        'sent_count': m.sent_count,
        'error_count': m.error_count,
        'created_at': m.created_at.isoformat()
    } for m in messages])

@app.route('/send_message', methods=['POST'])
def send_message():
    if 'session_string' not in session:
        return jsonify({'error': 'Необходима авторизация'}), 401

    data = request.get_json()
    if not data or 'text' not in data or not data['text'].strip():
        return jsonify({'error': 'Текст сообщения обязателен'}), 400

    message_text = data['text'].strip()
    
    # Create new message in database
    message = Message(
        text=message_text,
        status='pending',
        created_at=datetime.now(timezone.utc)
    )
    db.session.add(message)
    db.session.commit()

    async def send_messages_async():
        client = None
        try:
            client = await create_client()
            client.session.load(session['session_string'])
            await client.connect()
            
            # Get list of dialogs
            async for dialog in client.iter_dialogs():
                try:
                    # Send message
                    await client.send_message(dialog.id, message_text)
                    
                    # Create log entry
                    log = MessageLog(
                        message_id=message.id,
                        target=str(dialog.id),
                        status='success',
                        sent_at=datetime.now(timezone.utc)
                    )
                    db.session.add(log)
                    
                except Exception as e:
                    # Log sending error
                    log = MessageLog(
                        message_id=message.id,
                        target=str(dialog.id),
                        status='error',
                        error_message=str(e),
                        sent_at=datetime.now(timezone.utc)
                    )
                    db.session.add(log)
                
                db.session.commit()
            
            message.status = 'completed'
            db.session.commit()
            return {'success': True, 'message_id': message.id}
            
        except Exception as e:
            message.status = 'error'
            message.error_message = str(e)
            db.session.commit()
            return {'error': str(e)}, 500
            
        finally:
            if client:
                await client.disconnect()

    try:
        result = run_async(send_messages_async())
        if isinstance(result, tuple):
            return jsonify(result[0]), result[1]
        return jsonify(result)
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/get_dialogs')
def get_dialogs():
    if 'session_string' not in session:
        return jsonify({'error': 'Не авторизован'}), 401

    async def get_dialogs_async():
        client = None
        try:
            client = await create_client()
            client.session.load(session['session_string'])
            await client.connect()

            if not await client.is_user_authorized():
                return {'error': 'Не авторизован'}, 401

            dialogs = []
            async for dialog in client.iter_dialogs():
                try:
                    dialogs.append({
                        'id': dialog.id,
                        'title': dialog.title,
                        'type': str(dialog.entity.__class__.__name__),
                        'unread_count': dialog.unread_count,
                        'is_group': hasattr(dialog.entity, 'participants_count')
                    })
                except Exception as e:
                    app.logger.error(f'Error processing dialog {dialog.id}: {str(e)}')
                    continue

            return {'results': dialogs}

        except Exception as e:
            app.logger.error(f'Error in get_dialogs: {str(e)}')
            return {'error': str(e)}, 500
        finally:
            if client:
                await client.disconnect()

    try:
        result = run_async(get_dialogs_async())
        if isinstance(result, tuple):
            return jsonify(result[0]), result[1]
        return jsonify(result)
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/check_auth', methods=['GET'])
async def check_auth():
    if 'session_string' not in session:
        return jsonify({'authenticated': False})

    try:
        client = await create_client()
        client.session.load(session['session_string'])
        
        try:
            await client.connect()
            if not await client.is_user_authorized():
                session.pop('session_string', None)
                return jsonify({'authenticated': False})
            return jsonify({'authenticated': True})
        finally:
            await client.disconnect()
            
    except Exception as e:
        app.logger.error(f'Error in check_auth: {str(e)}')
        return jsonify({'authenticated': False})

if __name__ == '__main__':
    app.run(debug=True)
