
# Usar una imagen base de Python
FROM python:3.9-slim

# Instalar dependencias necesarias
RUN apt-get update && \
    apt-get install -y \
    iputils-ping \
    nmap \
    tcpdump \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# Establecer directorio de trabajo
WORKDIR /app

# Copiar el script
COPY erantzuten.py .

# Variables de entorno para configuración
ENV LISTEN_IP=""

# Permisos de root para sockets raw
USER root

# Comando por defecto
CMD if [ -z "$LISTEN_IP" ]; then \
        echo "ERROR: Debes proporcionar LISTEN_IP"; \
        exit 1; \
    else \
        python3 erantzuten.py "$LISTEN_IP"; \
    fi