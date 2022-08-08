FROM python:3.8-slim-buster

WORKDIR /app
RUN touch requirements.txt
COPY requirements.txt requirements.txt

RUN pip3 install --upgrade pip
RUN pip3 install -r requirements.txt
COPY . .

RUN apt-get update
RUN apt-get install net-tools


WORKDIR /app/papayafoodcourt
COPY cert.pem cert.pem
COPY key.pem key.pem
COPY requirements.txt requirements.txt

RUN python app.py --cert=cert.pem --key=key.pem
