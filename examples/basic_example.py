"""
Базовый пример использования yukinoise-auth в FastAPI приложении.

Этот пример демонстрирует:
- Инициализацию библиотеки
- Защиту эндпоинтов с помощью dependency injection
- Проверку ролей и прав доступа
"""

from contextlib import asynccontextmanager
from typing import Annotated

from fastapi import Depends, FastAPI

from yukinoise_auth import (
    KeycloakSettings,
    Principal,
    get_current_principal,
    get_optional_principal,
    init_auth,
    require_any_realm_role,
    require_realm_role,
)


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Lifespan context manager для инициализации и очистки ресурсов."""
    # Startup: инициализация аутентификации
    settings = KeycloakSettings()
    init_auth(settings)
    print(f"Auth initialized with Keycloak at {settings.server_url}")
    yield
    # Shutdown: очистка ресурсов (если необходимо)
    print("Shutting down...")


# Создание FastAPI приложения
app = FastAPI(
    title="YukiNoise Auth Example",
    description="Пример использования yukinoise-auth",
    version="1.0.0",
    lifespan=lifespan
)


@app.get("/")
async def root():
    """Публичный эндпоинт без аутентификации."""
    return {
        "message": "YukiNoise Auth Example API",
        "docs": "/docs"
    }


@app.get("/health")
async def health_check():
    """Health check эндпоинт."""
    return {"status": "healthy"}


@app.get("/api/me")
async def get_current_user(
    principal: Annotated[Principal, Depends(get_current_principal)]
):
    """Получить информацию о текущем пользователе."""
    return {
        "user_id": principal.user_id,
        "username": principal.username,
        "email": principal.email,
        "name": principal.name,
        "realm_roles": principal.realm_roles,
        "groups": principal.groups
    }


@app.get("/api/public")
async def public_route(
    principal: Annotated[Principal | None, Depends(get_optional_principal)]
):
    """Публичный эндпоинт с опциональной аутентификацией."""
    if principal:
        return {
            "message": f"Hello, {principal.username}!",
            "authenticated": True
        }
    return {
        "message": "Hello, anonymous user!",
        "authenticated": False
    }


@app.get("/api/protected")
async def protected_route(
    principal: Annotated[Principal, Depends(get_current_principal)]
):
    """Защищенный эндпоинт - требуется аутентификация."""
    return {
        "message": "This is a protected resource",
        "accessed_by": principal.username
    }


@app.get("/api/admin")
async def admin_only(
    principal: Annotated[Principal, Depends(require_realm_role("admin"))]
):
    """Эндпоинт только для администраторов."""
    return {
        "message": "Welcome, admin!",
        "admin_user": principal.username
    }


@app.get("/api/moderator")
async def moderator_route(
    principal: Annotated[Principal, Depends(require_any_realm_role("admin", "moderator"))]
):
    """Эндпоинт для администраторов и модераторов."""
    return {
        "message": "Welcome, moderator or admin!",
        "user": principal.username,
        "roles": principal.realm_roles
    }


@app.post("/api/users")
async def create_user(
    principal: Annotated[Principal, Depends(require_realm_role("user-manager"))]
):
    """Создание пользователя - требуется роль user-manager."""
    # Здесь была бы логика создания пользователя
    return {
        "message": "User created successfully",
        "created_by": principal.username
    }


@app.delete("/api/users/{user_id}")
async def delete_user(
    user_id: str,
    principal: Annotated[Principal, Depends(require_any_realm_role("admin", "user-manager"))]
):
    """Удаление пользователя - требуется роль admin или user-manager."""
    # Здесь была бы логика удаления пользователя
    return {
        "message": f"User {user_id} deleted successfully",
        "deleted_by": principal.username
    }


@app.get("/api/profile/{user_id}")
async def get_user_profile(
    user_id: str,
    principal: Annotated[Principal, Depends(get_current_principal)]
):
    """Получить профиль пользователя.
    
    Пользователь может получить только свой профиль,
    или любой профиль, если у него есть роль admin.
    """
    # Проверяем, может ли пользователь видеть этот профиль
    if principal.user_id != user_id and not principal.has_realm_role("admin"):
        return {
            "error": "You can only view your own profile"
        }, 403
    
    # Здесь была бы логика получения профиля
    return {
        "user_id": user_id,
        "accessed_by": principal.username
    }


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
