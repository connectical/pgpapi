FROM python:3-alpine3.6

COPY . /tmp/pgpapi

ARG HOST="0.0.0.0"
ARG PORT="11380"
ARG KEYSERVER="pgp.mit.edu"
ARG GNUPG_HOME="/var/cache/pgpapi"

RUN apk -U --no-progress add gcc gnupg musl-dev && \
  cd /tmp/pgpapi && \
  python setup.py install && \
  mkdir -p $GNUPG_HOME && \
  chown nobody:nobody $GNUPG_HOME && \
  apk --no-progress del gcc musl-dev && \
  rm -rf /root/.ash_history /tmp/pgpapi /var/cache/apk/*

ENV PGPAPI_HOST="$HOST" \
  PGPAPI_PORT="$PORT" \
  PGPAPI_ENVIRON="production" \
  PGPAPI_KEYSERVER="$KEYSERVER" \
  PGPAPI_GNUPG_HOME="$GNUPG_HOME" \
  PGPAPI_MAX_SEARCH_KEYS="40"

EXPOSE "$PORT"

VOLUME [ "$GNUPG_HOME" ]

USER nobody

ENTRYPOINT [ "/usr/local/bin/pgpapi", "server" ]
