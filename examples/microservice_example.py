"""
Пример микросервиса с полной интеграцией yukinoise-auth.

Этот пример демонстрирует:
- Настройку микросервиса с разными уровнями доступа
- Использование ролей и групп
- CRUD операции с проверкой прав
- Обработку ошибок аутентификации
"""

from contextlib import asynccontextmanager
from typing import Annotated

from fastapi import Depends, FastAPI, HTTPException, status
from fastapi.responses import JSONResponse
from pydantic import BaseModel

from yukinoise_auth import (
    AuthException,
    KeycloakSettings,
    Principal,
    get_current_principal,
    init_auth,
    require_any_realm_role,
    require_realm_role,
)


# Модели данных
class User(BaseModel):
    id: str
    username: str
    email: str
    active: bool = True


class UserCreate(BaseModel):
    username: str
    email: str


class UserUpdate(BaseModel):
    email: str | None = None
    active: bool | None = None


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Lifespan context manager для управления жизненным циклом приложения."""
    # Startup: инициализация
    settings = KeycloakSettings()
    init_auth(settings)
    print("User Management Service started")
    yield
    # Shutdown: очистка
    print("User Management Service stopped")


# Создание приложения
app = FastAPI(
    title="User Management Service",
    description="Микросервис управления пользователями с Keycloak аутентификацией",
    version="1.0.0",
    lifespan=lifespan
)


# Обработка ошибок аутентификации
@app.exception_handler(AuthException)
async def auth_exception_handler(request, exc: AuthException):
    return JSONResponse(
        status_code=exc.status_code,
        content={
            "error": "Authentication Error",
            "detail": exc.message
        }
    )


# === ПУБЛИЧНЫЕ ЭНДПОИНТЫ ===

@app.get("/")
async def root():
    return {
        "service": "User Management Service",
        "version": "1.0.0",
        "docs": "/docs"
    }


@app.get("/health")
async def health_check():
    return {"status": "healthy"}


# === ЗАЩИЩЕННЫЕ ЭНДПОИНТЫ ===

@app.get("/api/users/me")
async def get_my_profile(
    principal: Annotated[Principal, Depends(get_current_principal)]
):
    """Получить свой профиль (любой аутентифицированный пользователь)."""
    return {
        "id": principal.user_id,
        "username": principal.username,
        "email": principal.email,
        "roles": principal.realm_roles,
        "groups": principal.groups
    }


@app.get("/api/users", response_model=list[User])
async def list_users(
    principal: Annotated[Principal, Depends(require_any_realm_role("admin", "user-manager"))]
):
    """
    Получить список всех пользователей.
    Требуется роль: admin или user-manager
    """
    # В реальном приложении здесь был бы запрос к БД
    fake_users = [
        User(id="1", username="user1", email="user1@example.com"),
        User(id="2", username="user2", email="user2@example.com"),
    ]
    return fake_users


@app.get("/api/users/{user_id}")
async def get_user(
    user_id: str,
    principal: Annotated[Principal, Depends(get_current_principal)]
):
    """
    Получить информацию о пользователе.
    
    Пользователь может получить:
    - Свою информацию
    - Информацию других пользователей, если есть роль admin или user-viewer
    """
    # Проверка прав доступа
    can_view_others = (
        principal.has_any_realm_role(["admin", "user-viewer"]) or
        principal.user_id == user_id
    )
    
    if not can_view_others:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="You can only view your own profile"
        )
    
    # В реальном приложении - запрос к БД
    return User(
        id=user_id,
        username=f"user_{user_id}",
        email=f"user_{user_id}@example.com"
    )


@app.post("/api/users", response_model=User, status_code=status.HTTP_201_CREATED)
async def create_user(
    user_data: UserCreate,
    principal: Annotated[Principal, Depends(require_realm_role("user-manager"))]
):
    """
    Создать нового пользователя.
    Требуется роль: user-manager
    """
    # В реальном приложении - создание в БД
    new_user = User(
        id="new-id",
        username=user_data.username,
        email=user_data.email
    )
    
    print(f"User {new_user.username} created by {principal.username}")
    return new_user


@app.patch("/api/users/{user_id}")
async def update_user(
    user_id: str,
    update_data: UserUpdate,
    principal: Annotated[Principal, Depends(get_current_principal)]
):
    """
    Обновить пользователя.
    
    Пользователь может обновить:
    - Свои данные (кроме active)
    - Любые данные, если есть роль user-manager
    """
    is_own_profile = principal.user_id == user_id
    is_manager = principal.has_realm_role("user-manager")
    
    # Проверка прав
    if not is_own_profile and not is_manager:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="You can only update your own profile"
        )
    
    # Только managers могут менять статус active
    if update_data.active is not None and not is_manager:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Only user managers can change active status"
        )
    
    # В реальном приложении - обновление в БД
    return {
        "message": "User updated successfully",
        "user_id": user_id,
        "updated_by": principal.username
    }


@app.delete("/api/users/{user_id}")
async def delete_user(
    user_id: str,
    principal: Annotated[Principal, Depends(require_realm_role("admin"))]
):
    """
    Удалить пользователя.
    Требуется роль: admin
    """
    # Запретить удаление самого себя
    if principal.user_id == user_id:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="You cannot delete yourself"
        )
    
    # В реальном приложении - удаление из БД
    return {
        "message": f"User {user_id} deleted successfully",
        "deleted_by": principal.username
    }


# === VIP ФУНКЦИОНАЛ (ГРУППЫ) ===

@app.get("/api/vip/content")
async def get_vip_content(
    principal: Annotated[Principal, Depends(get_current_principal)]
):
    """
    Получить VIP контент.
    Требуется членство в группе /vip-users
    """
    if not principal.in_group("/vip-users"):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="VIP membership required"
        )
    
    return {
        "content": "Exclusive VIP content",
        "user": principal.username
    }


# === СТАТИСТИКА (ADMIN) ===

@app.get("/api/admin/stats")
async def get_statistics(
    principal: Annotated[Principal, Depends(require_realm_role("admin"))]
):
    """
    Получить статистику системы.
    Требуется роль: admin
    """
    return {
        "total_users": 42,
        "active_users": 38,
        "requested_by": principal.username
    }


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8002)
