"""Authentication business logic: registration and login."""
from sqlalchemy.orm import Session

from app.core.exceptions import AppError, UnauthorizedError
from app.core.security import create_access_token, hash_password, verify_password
from app.models.settings import UserSettings
from app.models.user import User
from app.repositories.user_repository import UserRepository
from app.schemas.auth import TokenResponse
from app.schemas.user import UserCreate


class AuthService:
    def __init__(self, db: Session):
        self.db = db
        self.repo = UserRepository(db)

    def register(self, payload: UserCreate) -> User:
        if self.repo.get_by_email(payload.email):
            raise AppError("An account with this email already exists.", status_code=409)

        user = User(
            email=payload.email,
            full_name=payload.full_name,
            hashed_password=hash_password(payload.password),
        )
        user = self.repo.create(user)

        self.db.add(UserSettings(user_id=user.id))
        self.db.commit()
        return user

    def login(self, email: str, password: str) -> TokenResponse:
        user = self.repo.get_by_email(email)
        if not user or not verify_password(password, user.hashed_password):
            raise UnauthorizedError("Invalid email or password.")
        if not user.is_active:
            raise UnauthorizedError("This account has been deactivated.")

        token = create_access_token(subject=user.id)
        return TokenResponse(access_token=token)
