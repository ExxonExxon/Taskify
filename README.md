# Taskify
To Do List Website

To start the site using gunicorn use this command you will need a SSL encryption

gunicorn app:app -w 4 -b 0.0.0.0:443 --keyfile /etc/letsencrypt/live/taskify.ddns.net/privkey.pem --certfile /etc/letsencrypt/live/taskify.ddns.net/fullchain.pem
