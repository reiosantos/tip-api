FROM ubuntu:16.04

MAINTAINER reiosantos "reiosantos@yahoo.com"

RUN apt-get update -y && apt-get install -y python3-pip python3-dev

# We copy just the requirements.txt first to leverage Docker cache
#COPY ./requirements.txt /app/requirements.txt

ADD requirements.txt /app/

WORKDIR /app

EXPOSE 5000

RUN pip3 install -r requirements.txt

ADD . /app

ENTRYPOINT ["python3"]

CMD ["app.py"]
