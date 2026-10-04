FROM python:3.12-alpine

WORKDIR /app
COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

COPY cybics_mgmt/ cybics_mgmt/
COPY cybics_ctf/ cybics_ctf/
COPY wsgi.py gunicorn.conf.py ./

# Unlike the CybICS training containers, this one is a real service on a
# shared network: run unprivileged and keep all state on the volume.
RUN adduser -D -H -u 10001 mgmt && mkdir -p /data && chown mgmt /data
USER mgmt
ENV MGMT_DATA_DIR=/data
VOLUME /data
EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s \
  CMD wget -qO- http://127.0.0.1:8000/healthz || exit 1

CMD ["gunicorn", "-c", "gunicorn.conf.py", "wsgi:app"]
