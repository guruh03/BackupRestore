#!/bin/sh

until cd /app/backend
do
    echo "Waiting for server volume..."
done

# until ./manage.py makemigrations
# do
#     echo "Waiting for db to be ready..."
#     sleep 2
# done

# until ./manage.py migrate
# do
#     echo "Waiting for db to be ready..."
#     sleep 2
# done

./manage.py deletionScript &

./manage.py collectstatic --noinput

gunicorn backup_and_restore.wsgi --bind 0.0.0.0:8005 --workers 4 --threads 4
