from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
import json
from datetime import datetime, timedelta
import jwt
import smtplib
from email.mime.text import MIMEText
from fastapi.responses import FileResponse
from fastapi.middleware.cors import CORSMiddleware
import bcrypt
from pydantic import BaseModel
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import Response

app = FastAPI()

class CSPMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request, call_next):
        response = await call_next(request)
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; "
            "script-src 'self' 'unsafe-inline'; "
            "style-src 'self' 'unsafe-inline'; "
            "img-src 'self' data:; "
            "font-src 'self'; "
            "connect-src 'self' http://localhost:8000; "
            "frame-ancestors 'none';"
        )
        return response

# Middleware'i ekle
app.add_middleware(CSPMiddleware)

# secretkey ile jwt arasındaki bağlantı 
# mail kendi mailimizden gönderiliyor
# mail ve şifresi direkt kodda olmasın
# endpointlere POST ile gitmeye çalışıldığı için linkden gidilmiyor GET kullanmak lazım postman kullan bunun için
# uvicorn app:app --reload

SECRET_KEY = "my_secret_key"  # Önce bu satır tanımlanmalı

# Fazla izin verdik gibi duruyor crossorigin
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Tüm domainlere izin ver (Güvenlik için production'da belirli domainler eklenmeli)
    allow_credentials=True,
    allow_methods=["*"],  # Tüm HTTP metotlarına izin ver (POST, GET, OPTIONS vb.)
    allow_headers=["*"],  # Tüm header'lara izin ver
)

# Fake database için JSON dosyası
def load_users_from_file():
    try:
        with open("users.json", "r") as file:
            return json.load(file)
    except FileNotFoundError:
        return {}

def save_users_to_file():
    try:
        with open("users.json", "w") as file:
            json.dump(users, file, indent=4)  # `users` sözlüğünü JSON dosyasına kaydediyoruz
    except Exception as e:
        print(f"JSON kaydetme hatası: {e}")  # Olası hataları görmek için


# Uygulama başlatıldığında JSON dosyasından kullanıcıları yükle
users = load_users_from_file()

# Kullanıcı modeli
class UserRegister(BaseModel):
    email: str
    password: str

# Kayıtlı kullanıcıları görüntüleme endpoint'i
@app.get("/users")
async def get_users():
    return users

@app.get("/verify-email")
async def verify_email(token: str):
    try:
        # Token'ı çöz
        payload = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
        email = payload.get("sub")
        if email in users:
            users[email]["is_email_verified"] = True  # Kullanıcıyı doğrula
            save_users_to_file()  # Güncellenen veriyi kaydet
            return {"message": "Email doğrulandı!"}
        raise HTTPException(status_code=404, detail="Kullanıcı bulunamadı")
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=400, detail="Token süresi dolmuş")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=400, detail="Geçersiz token")

@app.get("/")
async def serve_frontend():
    return FileResponse("index.html")

@app.get("/verify")
async def serve_verification_page():
    return FileResponse("verify.html")

@app.post("/register")
async def register(user: UserRegister):
    email = user.email
    password = user.password  # Kullanıcının girdiği şifre
    
    if email in users:
        raise HTTPException(status_code=400, detail="Kullanıcı zaten mevcut")
    
    # Şifreyi hashle ve kullanıcıyı fake database'e ekle
    hashed_password = hash_password(password)
    
    users[email] = {
        "id": str(len(users) + 1),
        "email": email,
        "password": hashed_password,  # Hashlenmiş şifreyi kaydediyoruz
        "is_email_verified": False,
    }

    # Token oluştur ve email gönder
    token = generate_email_verification_token(email)
    send_email(email, token)

    # JSON dosyasına kaydet
    save_users_to_file()
    
    return {"message": "Kayıt başarılı, email doğrulama bekleniyor!"}

class UserLogin(BaseModel):
    email: str
    password: str

@app.post("/login")
async def login(user: UserLogin):
    email = user.email
    password = user.password  # Kullanıcının girdiği şifre
    
    # Kullanıcı kayıtlı mı?
    if email not in users:
        raise HTTPException(status_code=400, detail="Kullanıcı bulunamadı")
    
    stored_hashed_password = users[email]["password"]  # JSON'da kayıtlı hashlenmiş şifre
    
    # Şifre doğru mu?
    if not verify_password(password, stored_hashed_password):
        raise HTTPException(status_code=400, detail="Yanlış şifre")

    # Eğer şifre doğruysa JWT token oluştur
    access_token = generate_access_token(email)

    return {"access_token": access_token, "token_type": "bearer"}


def generate_email_verification_token(email: str) -> str:
    payload = {
        "sub": email,
        "exp": (datetime.utcnow() + timedelta(hours=6)).timestamp(),  # Token 6 saat geçerli
    }
    return jwt.encode(payload, SECRET_KEY, algorithm="HS256")


def send_email(to_email: str, token: str):
    link = f"http://localhost:8000/verify?token={token}"  # Güncellendi
    message = MIMEText(f"Emailinizi doğrulamak için şu linke tıklayın: <a href='{link}'>Doğrula</a>", "html")
    message["Subject"] = "Email Doğrulama"
    message["From"] = "talhaaeroglu1@gmail.com"
    message["To"] = to_email

    with smtplib.SMTP("smtp.gmail.com", 587) as server:
        server.starttls()
        server.login("talhaaeroglu1@gmail.com", "khnj bbxo cqxy xxjf")
        server.sendmail("talhaaerolgu1@gmail.com", to_email, message.as_string())

def hash_password(password: str) -> str:
    salt = bcrypt.gensalt()
    hashed_password = bcrypt.hashpw(password.encode('utf-8'), salt)
    return hashed_password.decode('utf-8')

def verify_password(plain_password: str, hashed_password: str) -> bool:
    return bcrypt.checkpw(plain_password.encode('utf-8'), hashed_password.encode('utf-8'))

def generate_access_token(email: str) -> str:
    payload = {
        "sub": email,
        "exp": (datetime.utcnow() + timedelta(hours=1)).timestamp(),  # Token 1 saat geçerli
        "token_type": "access_token",
    }
    return jwt.encode(payload, SECRET_KEY, algorithm="HS256")

class ResetPasswordRequest(BaseModel):
    email: str

@app.post("/reset-password-request")
async def reset_password_request(request: ResetPasswordRequest):
    email = request.email

    # Kullanıcı kayıtlı mı?
    if email not in users:
        raise HTTPException(status_code=400, detail="Kullanıcı bulunamadı")
    
    # Şifre sıfırlama tokeni oluştur
    reset_token = generate_reset_token(email)

    # Kullanıcıya email gönder
    send_reset_email(email, reset_token)

    return {"message": "Şifre sıfırlama linki email adresinize gönderildi!"}

def generate_reset_token(email: str) -> str:
    payload = {
        "sub": email,
        "exp": (datetime.utcnow() + timedelta(minutes=300)).timestamp(),  # Token 300 dakika geçerli
        "token_type": "password_reset"
    }
    return jwt.encode(payload, SECRET_KEY, algorithm="HS256")

def send_reset_email(to_email: str, token: str):
    link = f"http://localhost:8000/reset-password?token={token}"  # Kullanıcı bu linke tıklayacak
    message = MIMEText(f"Şifrenizi sıfırlamak için şu linke tıklayın: <a href='{link}'>Şifre Sıfırla</a>", "html")
    message["Subject"] = "Şifre Sıfırlama"
    message["From"] = "talhaaeroglu1@gmail.com"
    message["To"] = to_email

    with smtplib.SMTP("smtp.gmail.com", 587) as server:
        server.starttls()
        server.login("talhaaeroglu1@gmail.com", "khnj bbxo cqxy xxjf")
        server.sendmail("talhaaeroglu1@gmail.com", to_email, message.as_string())

class ResetPassword(BaseModel):
    token: str
    new_password: str

@app.post("/reset-password")
async def reset_password(data: ResetPassword):
    try:
        # Token'i doğrula
        payload = jwt.decode(data.token, SECRET_KEY, algorithms=["HS256"])
        email = payload.get("sub")

        # Token tipi kontrolü
        if payload.get("token_type") != "password_reset":
            raise HTTPException(status_code=400, detail="Geçersiz token türü!")

        # Kullanıcı mevcut mu?
        if email not in users:
            raise HTTPException(status_code=400, detail="Kullanıcı bulunamadı!")

        # Yeni şifreyi hashle ve kaydet
        hashed_password = hash_password(data.new_password)
        users[email]["password"] = hashed_password

        # JSON dosyasına güncelleme yap
        save_users_to_file()

        return {"message": "Şifre başarıyla güncellendi!"}

    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=400, detail="Token süresi dolmuş!")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=400, detail="Geçersiz token!")
