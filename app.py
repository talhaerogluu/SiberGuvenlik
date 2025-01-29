from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
import json
from datetime import datetime, timedelta
import jwt
import smtplib
from email.mime.text import MIMEText

# secretkey ile jwt arasındaki bağlantı 
# mail kendi mailimizden gönderiliyor
# mail ve şifresi direkt kodda olmasın

app = FastAPI()
SECRET_KEY = "my_secret_key"  # Önce bu satır tanımlanmalı

# Fake database için JSON dosyası
def load_users_from_file():
    try:
        with open("users.json", "r") as file:
            return json.load(file)
    except FileNotFoundError:
        return {}

def save_users_to_file(users):
    with open("users.json", "w") as file:
        json.dump(users, file, indent=4)

# Uygulama başlatıldığında JSON dosyasından kullanıcıları yükle
users = load_users_from_file()

# Kullanıcı modeli
class UserRegister(BaseModel):
    email: str

# Kullanıcı kaydı endpoint'i
@app.post("/register")
async def register(user: UserRegister):
    email = user.email
    if email in users:
        raise HTTPException(status_code=400, detail="Kullanıcı zaten mevcut")
    
    # Kullanıcıyı fake database'e ekle
    users[email] = {
        "id": str(len(users) + 1),
        "email": email,
        "is_email_verified": False,
    }

    # Token oluştur ve email gönder
    token = generate_email_verification_token(email)
    send_email(email, token)

    # JSON dosyasına kaydet
    save_users_to_file(users)
    return {"message": "Kayıt başarılı, email doğrulama bekleniyor!"}

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
            save_users_to_file(users)  # Güncellenen veriyi kaydet
            return {"message": "Email doğrulandı!"}
        raise HTTPException(status_code=404, detail="Kullanıcı bulunamadı")
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=400, detail="Token süresi dolmuş")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=400, detail="Geçersiz token")


def generate_email_verification_token(email: str) -> str:
    payload = {
        "sub": email,
        "exp": (datetime.utcnow() + timedelta(hours=6)).timestamp(),  # Token 6 saat geçerli
    }
    return jwt.encode(payload, SECRET_KEY, algorithm="HS256")


def send_email(to_email: str, token: str):
    link = f"http://localhost:8000/verify-email?token={token}"
    message = MIMEText(f"Emailinizi doğrulamak için şu linke tıklayın: {link}")
    message["Subject"] = "Email Doğrulama"
    message["From"] = "talhaaeroglu1@gmail.com"
    message["To"] = to_email

    with smtplib.SMTP("smtp.gmail.com", 587) as server:
        server.starttls()
        server.login("talhaaeroglu1@gmail.com", "khnj bbxo cqxy xxjf")
        server.sendmail("talhaaerolgu1@gmail.com", to_email, message.as_string())