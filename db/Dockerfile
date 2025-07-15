FROM mysql:8.0

COPY ./writedb_usertbl.sql /docker-entrypoint-initdb.d

ENV MYSQL_ROOT_PASSWORD=1234
ENV MYSQL_DATABASE=writedb
