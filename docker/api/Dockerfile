FROM python:3.6-slim

RUN apt update -y \
    && apt install -y python3-dev openssl unixodbc-dev wget build-essential \
    && apt clean

RUN wget -O /tmp/mysql-connector-odbc-8.0.20-linux-glibc2.12-x86-64bit.tar.gz https://cdn.mysql.com//Downloads/Connector-ODBC/8.0/mysql-connector-odbc-8.0.20-linux-glibc2.12-x86-64bit.tar.gz \
    && tar xf /tmp/mysql-connector-odbc-8.0.20-linux-glibc2.12-x86-64bit.tar.gz -C /tmp \
    && mv /tmp/mysql-connector-odbc-8.0.20-linux-glibc2.12-x86-64bit/bin/* /usr/local/bin/. \
    && mv /tmp/mysql-connector-odbc-8.0.20-linux-glibc2.12-x86-64bit/lib/* /usr/local/lib/. \
    && chmod 777 /usr/local/lib/libmyodbc* \
    && rm -rf /tmp/mysql-connector-odbc-8.0.20-linux-glibc2.12-x86-64bit*

COPY odbcinst.ini /etc
COPY requirements.txt .

RUN pip install --no-cache-dir -U pip \
    && pip install --no-cache-dir -r requirements.txt
