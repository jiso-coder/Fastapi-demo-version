from fastapi import FastAPI, Depends, HTTPException
from sqlalchemy.orm import Session
from . import models, schemas, database, email_utils, auth

models.Base.metadata.create_all(bind=database.engine)

app = FastAPI()

def get_db():
    db = database.SessionLocal()
    try:
        yield db
    finally:
        db.close()

@app.post("/register")
def register(user: schemas.UserCreate, db: Session = Depends(get_db)):
    existing = db.query(models.User).filter(models.User.email == user.email).first()
    if existing:
        raise HTTPException(status_code=400, detail="Email already registered")

    otp = email_utils.generate_otp()
    email_utils.send_email(user.email, otp)

    hashed_pw = auth.hash_password(user.password)
    new_user = models.User(email=user.email, hashed_password=hashed_pw, otp=otp, is_verified=False)
    db.add(new_user)
    db.commit()
    db.refresh(new_user)
    return {"msg": "OTP sent to email. Verify with /verify-otp"}

@app.post("/verify-otp")
def verify_otp(data: schemas.OTPVerify, db: Session = Depends(get_db)):
    user = db.query(models.User).filter(models.User.email == data.email).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    if user.otp != data.otp:
        raise HTTPException(status_code=400, detail="Invalid OTP")
    user.is_verified = True
    user.otp = None
    db.commit()
    return {"msg": "Email verified successfully"}

@app.post("/login")
def login(user: schemas.UserLogin, db: Session = Depends(get_db)):
    db_user = db.query(models.User).filter(models.User.email == user.email).first()
    if not db_user or not auth.verify_password(user.password, db_user.hashed_password):
        raise HTTPException(status_code=401, detail="Invalid credentials")
    if not db_user.is_verified:
        raise HTTPException(status_code=403, detail="Email not verified")
    token = auth.create_access_token({"sub": db_user.email})
    return {"access_token": token, "token_type": "bearer"}

@app.post("/forgot-password")
def forgot_password(req: schemas.PasswordResetRequest, db: Session = Depends(get_db)):
    user = db.query(models.User).filter(models.User.email == req.email).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    otp = email_utils.generate_otp()
    user.otp = otp
    db.commit()
    email_utils.send_email(user.email, otp)
    return {"msg": "OTP sent for password reset"}

@app.post("/reset-password")
def reset_password(data: schemas.PasswordResetConfirm, db: Session = Depends(get_db)):
    user = db.query(models.User).filter(models.User.email == data.email).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    if user.otp != data.otp:
        raise HTTPException(status_code=400, detail="Invalid OTP")
    user.hashed_password = auth.hash_password(data.new_password)
    user.otp = None
    db.commit()
    return {"msg": "Password reset successful"}
