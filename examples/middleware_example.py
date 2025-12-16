"""
Пример использования Middleware для автоматической проверки токенов.

Этот пример демонстрирует:
- Использование KeycloakAuthMiddleware
- Настройку публичных и опциональных путей
- Доступ к Principal через request.state
"""

from fastapi import FastAPI, Request

from yukinoise_auth import KeycloakAuthMiddleware, KeycloakSettings

app = FastAPI(
    title="YukiNoise Auth Middleware Example",
    description="Пример использования middleware",
    version="1.0.0"
)

settings = KeycloakSettings()

app.add_middleware(
    KeycloakAuthMiddleware,
    settings=settings,
    exclude_paths=[
        "/",
        "/health",
        "/docs",
        "/openapi.json",
        "/redoc"
    ],
    optional_paths=[
        "/api/public"
    ]
)


@app.get("/")
async def root():
    """Публичный эндпоинт (исключен из middleware)."""
    return {
        "message": "YukiNoise Auth Middleware Example",
        "docs": "/docs"
    }


@app.get("/health")
async def health_check():
    """Health check (исключен из middleware)."""
    return {"status": "healthy"}


@app.get("/api/public")
async def public_route(request: Request):
    """Публичный эндпоинт с опциональной аутентификацией."""
    principal = request.state.principal
    
    if principal:
        return {
            "message": f"Hello, {principal.username}!",
            "authenticated": True,
            "user_id": principal.user_id
        }
    return {
        "message": "Hello, anonymous user!",
        "authenticated": False
    }


@app.get("/api/profile")
async def get_profile(request: Request):
    """
    Получить профиль текущего пользователя.
    
    Middleware автоматически проверит токен и
    добавит Principal в request.state
    """
    principal = request.state.principal
    
    return {
        "user_id": principal.user_id,
        "username": principal.username,
        "email": principal.email,
        "name": principal.name,
        "roles": principal.realm_roles
    }


@app.get("/api/data")
async def get_data(request: Request):
    """Получить данные (требуется аутентификация через middleware)."""
    principal = request.state.principal
    
    return {
        "data": "Some sensitive data",
        "accessed_by": principal.username,
        "user_id": principal.user_id
    }


@app.post("/api/items")
async def create_item(request: Request, item_data: dict):
    """Создать элемент (требуется аутентификация)."""
    principal = request.state.principal
    
    # Проверка ролей
    if not principal.has_realm_role("user"):
        return {
            "error": "Insufficient permissions"
        }, 403
    
    return {
        "message": "Item created",
        "created_by": principal.username,
        "item_data": item_data
    }


@app.delete("/api/items/{item_id}")
async def delete_item(item_id: str, request: Request):
    """Удалить элемент (требуется роль admin)."""
    principal = request.state.principal

    # Проверка admin роли
    if not principal.has_realm_role("admin"):
        return {
            "error": "Only admins can delete items"
        }, 403

    return {
        "message": f"Item {item_id} deleted",
        "deleted_by": principal.username
    }


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8001)
