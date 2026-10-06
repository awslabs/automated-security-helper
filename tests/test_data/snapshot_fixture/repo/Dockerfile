FROM python:3.12-slim
COPY app/ /srv/app/
COPY requirements.txt /srv/
RUN pip install -r /srv/requirements.txt
USER root
CMD ["python", "/srv/app/app.py"]
