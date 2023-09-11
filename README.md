# Taskify
To Do List Website

To start the site using gunicorn use this command you will need a SSL encryption

sudo gunicorn app:app -w 8 -k gevent -b 0.0.0.0:443 --keyfile /etc/letsencrypt/live/taskiy.co/privkey.pem --certfile /etc/letsencrypt/live/taskiy.co/fullchain.pem

