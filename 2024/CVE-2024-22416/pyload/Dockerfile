FROM python:3.10-alpine3.18
RUN apk update && apk add curl-dev python3-dev openssl-dev gcc libc-dev
RUN pip install pyload-ng==0.5.0b3.dev76 && mkdir -p /pyload/storage /pyload/user
COPY pyload.cfg /pyload/user/settings/pyload.cfg
CMD ["pyload", "--storagedir", "/pyload/storage", "--userdir", "/pyload/user"]
