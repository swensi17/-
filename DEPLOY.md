# Инструкция по развертыванию

## 1. Регистрация на PythonAnywhere
1. Перейдите на https://www.pythonanywhere.com/
2. Зарегистрируйте бесплатный аккаунт

## 2. Настройка веб-приложения
1. Перейдите в раздел "Web" на панели управления
2. Нажмите "Add a new web app"
3. Выберите "Flask" и Python 3.9
4. Укажите путь к файлу WSGI: `/home/YOUR_USERNAME/telegram-bot/wsgi.py`

## 3. Загрузка кода
1. Откройте консоль Bash на PythonAnywhere
2. Выполните команды:
```bash
git clone https://github.com/swensi17/-.git ~/telegram-bot
cd ~/telegram-bot
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

## 4. Настройка переменных окружения
1. В разделе "Web" найдите секцию "Environment variables"
2. Добавьте следующие переменные:
   - API_ID=ваш_api_id
   - API_HASH=ваш_api_hash
   - SECRET_KEY=ваш_секретный_ключ

## 5. Настройка WSGI файла
1. В разделе "Web" найдите и отредактируйте файл WSGI
2. Замените содержимое на код из файла wsgi.py

## 6. Перезапуск приложения
1. Нажмите "Reload" в разделе "Web"

## 7. Проверка
1. Перейдите по адресу: https://YOUR_USERNAME.pythonanywhere.com/

## Обновление кода
Для обновления кода на сервере:
1. Откройте консоль Bash
2. Выполните:
```bash
cd ~/telegram-bot
git pull
touch /var/www/YOUR_USERNAME_pythonanywhere_com_wsgi.py
```
