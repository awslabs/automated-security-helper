FROM python:3.12-slim@sha256:02108f5d322dd89f1c9e552442c25acb0543dfdbc455693a5599624f20d9155d
COPY app/ /srv/app/
COPY requirements.txt /srv/
RUN pip install -r /srv/requirements.txt
USER root
CMD ["python", "/srv/app/app.py"]
