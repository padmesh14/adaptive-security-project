FROM python:3.12-slim
WORKDIR /app
COPY requirements.txt ./requirements.txt
RUN pip install --no-cache-dir -r requirements.txt
COPY src ./src
COPY blockchain/integration ./blockchain/integration
COPY migrations ./migrations
COPY alembic.ini ./alembic.ini
COPY src/api/entrypoint.sh ./entrypoint.sh
RUN chmod 755 ./entrypoint.sh
EXPOSE 8000
CMD ["./entrypoint.sh"]
