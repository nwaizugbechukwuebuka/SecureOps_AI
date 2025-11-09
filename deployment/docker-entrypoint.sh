#!/bin/bash
set -e

# SecureOps Docker Entrypoint Script
# Author: Chukwuebuka Tobiloba Nwaizugbe

echo "Starting SecureOps Backend..."

# Wait for PostgreSQL to be ready
if [ -n "$DATABASE_URL" ]; then
    echo "Waiting for PostgreSQL..."
    while ! pg_isready -h db -p 5432 -U ${POSTGRES_USER:-postgres}; do
        echo "PostgreSQL is unavailable - sleeping"
        sleep 2
    done
    echo "PostgreSQL is up - continuing..."
fi

# Wait for Redis to be ready
if [ -n "$REDIS_URL" ]; then
    echo "Waiting for Redis..."
    while ! timeout 1 bash -c "echo > /dev/tcp/redis/6379" 2>/dev/null; do
        echo "Redis is unavailable - sleeping"
        sleep 2
    done
    echo "Redis is up - continuing..."
fi

# Run database migrations
echo "Running database migrations..."
cd /app
python -c "
from src.api.database import init_database

if __name__ == '__main__':
    init_database()"
    await init_db()
    print('Database initialized successfully')

if __name__ == '__main__':
    asyncio.run(main())
>>>>>>> 7c10f27ecb7c8b1a33ad81e0ccc85bf68459bdc3
"

# Create initial admin user if environment variables are provided
if [ -n "$INITIAL_ADMIN_EMAIL" ] && [ -n "$INITIAL_ADMIN_PASSWORD" ]; then
    echo "Creating initial admin user..."
    python -c "
import asyncio
from src.api.database import get_db_session
from src.api.models.user import User
from src.api.utils.auth import get_password_hash
from datetime import datetime, timezone

async def create_admin():
    async with get_db_session() as db:
        # Check if admin exists
        from sqlalchemy import select
        result = await db.execute(select(User).where(User.email == '$INITIAL_ADMIN_EMAIL'))
        existing_user = result.scalar_one_or_none()
        
        if not existing_user:
            admin_user = User(
                email='$INITIAL_ADMIN_EMAIL',
                username='admin',
                full_name='Administrator',
                hashed_password=get_password_hash('$INITIAL_ADMIN_PASSWORD'),
                is_active=True,
                is_superuser=True,
                created_at=datetime.now(timezone.utc)
            )
            db.add(admin_user)
            await db.commit()
            print('Admin user created successfully')
        else:
            print('Admin user already exists')

if __name__ == '__main__':
    asyncio.run(create_admin())
"
fi

# Start the application based on the command
if [ "$1" = "worker" ]; then
    echo "Starting Celery Worker..."
    exec celery -A src.tasks.celery_app worker --loglevel=info --concurrency=4
elif [ "$1" = "beat" ]; then
    echo "Starting Celery Beat..."
    exec celery -A src.tasks.celery_app beat --loglevel=info
elif [ "$1" = "flower" ]; then
    echo "Starting Celery Flower..."
    exec celery -A src.tasks.celery_app flower --port=5555
elif [ "$1" = "migrate" ]; then
    echo "Running migrations only..."
    exit 0
else
    echo "Starting FastAPI server..."
    exec "$@"
fi