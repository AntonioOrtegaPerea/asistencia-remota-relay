FROM python:3.12-slim

WORKDIR /app

COPY requirements-relay.txt .
RUN pip install --no-cache-dir -r requirements-relay.txt

COPY relay_server.py .
COPY remote_desk/__init__.py remote_desk/__init__.py
COPY remote_desk/config.py remote_desk/config.py
COPY remote_desk/crypto.py remote_desk/crypto.py
COPY remote_desk/relay.py remote_desk/relay.py
COPY remote_desk/web_console/ remote_desk/web_console/

ENV PORT=8765
EXPOSE 8765

CMD ["python", "relay_server.py"]
