# just for local tests

FROM php:7.2-apache

USER root

ENV NODE_VERSION v12.18.4

RUN apt-get update && apt-get -y install wget \
    tar \
    xz-utils \
    git \
    cmake \
    gzip \
    libxml2-dev \
    && wget -U "nodejs" -q -O nodejs.tar.xz https://nodejs.org/dist/${NODE_VERSION}/node-${NODE_VERSION}-linux-x64.tar.xz \
    && tar -xJf "nodejs.tar.xz" -C /usr/local --strip-components=1 --no-same-owner \
    && rm nodejs.tar.xz \
    && ln -s /usr/local/bin/node /usr/local/bin/nodejs \
    # create user
    && useradd -r -d /opt/webissues -c "Webissues User" -s /bin/bash -g www-data webissues \
    && mkdir /opt/webissues \
    && chown webissues:www-data /opt/webissues \
    && mkdir /srv/www && mkdir /srv/www/htdocs && chown webissues:www-data /srv/www/htdocs

ENV APACHE_SERVER_NAME securitybugtracker.io
ENV APACHE_DOCUMENT_ROOT /srv/www/htdocs
ENV APACHE_SSL_PORT 10443
ENV APACHE_HTTP_PORT 1080

COPY ./config/securitybugtracker-vhost.conf /etc/apache2/sites-available/000-default.conf

RUN sed -i "s/Listen 80/Listen ${APACHE_HTTP_PORT}/g" /etc/apache2/ports.conf \
    && sed -i "s/:80/:${APACHE_HTTP_PORT}/g" /etc/apache2/sites-enabled/* \
    && sed -i "s/Listen 443/Listen ${APACHE_SSL_PORT}/g" /etc/apache2/ports.conf \
    && sed -i "s/:443/:${APACHE_SSL_PORT}/g" /etc/apache2/sites-enabled/* \
    && sed -ri -e 's!/var/www/html!${APACHE_DOCUMENT_ROOT}!g' /etc/apache2/sites-available/*.conf \
    && sed -ri -e 's!/var/www/!${APACHE_DOCUMENT_ROOT}!g' /etc/apache2/apache2.conf /etc/apache2/conf-available/*.conf \
    && echo "ServerName localhost" >> /etc/apache2/apache2.conf \
    && a2enmod rewrite \
    && docker-php-ext-install mysqli pdo pdo_mysql soap && docker-php-ext-enable mysqli

USER webissues

COPY ./webissues-server-2.0.0/ /opt/webissues/webissues-server-2.0.0/

RUN git clone -b v2.0.2 https://github.com/mimecorg/webissues /srv/www/htdocs/webissues \
    && cd /srv/www/htdocs/webissues \
    && npm install \
    && npm run build:web \
    && cp -r /opt/webissues/webissues-server-2.0.0/client/* /srv/www/htdocs/webissues/client/ \
    && cp -r /opt/webissues/webissues-server-2.0.0/common/* /srv/www/htdocs/webissues/common/ \
    && cp -r /opt/webissues/webissues-server-2.0.0/setup/* /srv/www/htdocs/webissues/setup/ \
    && cp /opt/webissues/webissues-server-2.0.0/system/web/* /srv/www/htdocs/webissues/system/web/

EXPOSE 1080
EXPOSE 10443

ENTRYPOINT ["/usr/sbin/apache2ctl", "-DFOREGROUND"]
