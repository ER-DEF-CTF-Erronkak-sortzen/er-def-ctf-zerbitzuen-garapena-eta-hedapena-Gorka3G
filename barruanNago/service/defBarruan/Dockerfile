#  Python
FROM python:3.9-slim


RUN apt-get update && \
    apt-get install -y \
    iputils-ping \
    nmap \
    tcpdump \
    cron \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*


WORKDIR /app

COPY bidaltzen.py .


# Konfigurazio aldagaiak. Nora eta zer bidali
ENV DEST_IP=""
ENV BASH_COMMAND=""

#  cron minutuero egikaritzeko
RUN echo "* * * * * root python3 /app/bidaltzen.py $DEST_IP '$BASH_COMMAND' >> /var/log/cron.log 2>&1" > /etc/cron.d/bidaltzen-cron

# cron baimenak
RUN chmod 0644 /etc/cron.d/bidaltzen-cron

# root baimenak
USER root


CMD if [ -z "$DEST_IP" ] || [ -z "$BASH_COMMAND" ]; then \
        echo "ERROR: Debes proporcionar DEST_IP y BASH_COMMAND"; \
        exit 1; \
    else \
        # Iniciar cron en primer plano
        cron && \
        # Mantener el contenedor en ejecución
        tail -f /var/log/cron.log; \
    fi