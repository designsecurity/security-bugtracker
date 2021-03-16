FROM opensuse/leap:latest

USER root

ENV NODE_VERSION v12.18.4

RUN zypper refresh \
    && zypper -n install wget \
    tar \
    unzip \
    xz \
    postgresql \
    postgresql-devel \
    postgresql-contrib \
    postgresql10 \
    postgresql10-devel \
    postgresql10-contrib \
    git \
    cmake \
    gcc-c++ \
    glib2-devel \
    libgnutls-devel \
    libssh-devel \
    redis \
    hiredis-devel \
    libxml2-devel \
    doxygen \
    libgcrypt-devel \
    libgpgme-devel \
    bison \
    libksba-devel \
    libpcap-devel \
    libical-devel \
    python3 \
    python3-setuptools \
    python3-pip \
    python3-devel \
    curl \
    gettext-runtime \
    libmicrohttpd-devel \
    gzip \
    php7 \
    apache2 \
    apache2-prefork \
    apache2-mod_php7 \
    php7-soap \
    maven-lib \
    java-11-openjdk \
    java-11-openjdk-devel \
    nmap \
    w3m \
    lynx \
    gnutls \
    perl-XML-Twig \
    util-linux-systemd \
    sudo \
    # create an user
    && useradd -r -d /opt/gvm -c "GVM User" -s /bin/bash -g www gvm \
    && mkdir /opt/gvm \
    && chown gvm:www /opt/gvm \
    && mkdir /tmp/gvm-source && chown gvm:www /tmp/gvm-source \
    # apache/php needed by securitybugtracker openvas webservice
    && a2enmod php7 \
    # needed by gsa
    && wget -U "nodejs" -q -O nodejs.tar.xz https://nodejs.org/dist/${NODE_VERSION}/node-${NODE_VERSION}-linux-x64.tar.xz \
    && tar -xJf "nodejs.tar.xz" -C /usr/local --strip-components=1 --no-same-owner \
    && rm nodejs.tar.xz \
    && ln -s /usr/local/bin/node /usr/local/bin/nodejs

ENV APACHE_SERVER_NAME securitytools.io
ENV APACHE_DOCUMENT_ROOT /srv/www/htdocs
ENV APACHE_SSL_PORT 10443
ENV APACHE_HTTP_PORT 1080
ENV PATH="/usr/share/maven/bin/:${PATH}"

COPY ./config/securitytools-vhost.conf /etc/apache2/vhosts.d/000-default.conf

RUN sed -i "s/Listen 80/Listen ${APACHE_HTTP_PORT}/g" /etc/apache2/listen.conf \
    && sed -i "s/:80/:${APACHE_HTTP_PORT}/g" /etc/apache2/vhosts.d/* \
    && sed -i "s/Listen 443/Listen ${APACHE_SSL_PORT}/g" /etc/apache2/listen.conf \
    && sed -i "s/:443/:${APACHE_SSL_PORT}/g" /etc/apache2/vhosts.d/* \
    && sed -ri -e 's!/var/www/html!${APACHE_DOCUMENT_ROOT}!g' /etc/apache2/vhosts.d/*.conf \
    && sed -ri -e 's!/var/www/!${APACHE_DOCUMENT_ROOT}!g' /etc/apache2/httpd.conf /etc/apache2/vhosts.d/*.conf \
    && echo "ServerName localhost" >> /etc/apache2/httpd.conf \
    && chown gvm:www /usr/sbin/start_apache2 \
    && chmod g+x /usr/sbin/start_apache2 \
    && chown -R gvm:www /etc/apache2/ \
    && chmod -R g+w /etc/apache2/ \
    && chown -R gvm:www /var/log/apache2/ \
    && chmod -R g+w /var/log/apache2/ \
    && chown gvm:www /run/ \
    && chmod g+w /run/ \
    # other security tools
    && git clone https://github.com/rbsec/sslscan.git /tmp/sslscan && cd /tmp/sslscan && make && make install \
    && git clone -b v6.0.5 https://github.com/jeremylong/DependencyCheck /tmp/DependencyCheck && cd /tmp/DependencyCheck && mvn -U -Dmaven.wagon.http.retryHandler.count=3 -DskipTests -Dmaven.test.skip=true -s settings.xml install

USER gvm

WORKDIR /tmp/gvm-source 

ENV PKG_CONFIG_PATH="/opt/gvm/lib/pkgconfig:${PKG_CONFIG_PATH}"
ENV PATH="/usr/share/maven/bin/:/opt/gvm/bin:/opt/gvm/sbin:/opt/gvm/.local/bin:/opt/gvm/.venv/gvm-tools-1rWiyfLP-py3.6/bin/:${PATH}"
ENV PYTHONPATH="/opt/gvm/lib/python3.6/site-packages/"
ENV LD_LIBRARY_PATH="/opt/gvm/lib/:${LD_LIBRARY_PATH}"

RUN git clone -b gvm-libs-20.08 --single-branch https://github.com/greenbone/gvm-libs.git \
    && git clone -b openvas-20.08 --single-branch https://github.com/greenbone/openvas.git \
    && git clone -b gvmd-20.08 --single-branch https://github.com/greenbone/gvmd.git \
    && git clone -b gsa-20.08 --single-branch https://github.com/greenbone/gsa.git \
    && cd /tmp/gvm-source/gvm-libs/ \ 
    && mkdir build \ 
    && cd build \ 
    && cmake .. -DCMAKE_INSTALL_PREFIX=/opt/gvm \ 
    && make \ 
    && make install \
    && cd /tmp/gvm-source/openvas/ \ 
    && mkdir build \ 
    && cd build \ 
    && cmake .. -DCMAKE_INSTALL_PREFIX=/opt/gvm \ 
    && make \ 
    && make install \
    && cd /tmp/gvm-source/gvmd \ 
    && sed -i 's/#include <postgresql\/libpq-fe.h>/#include <pgsql\/libpq-fe.h>/' src/sql_pg.c \
    && mkdir build \ 
    && cd build \ 
    && cmake .. -DCMAKE_INSTALL_PREFIX=/opt/gvm \ 
    && make \ 
    && make install \
    && cd /tmp/gvm-source/gsa \ 
    && mkdir build \ 
    && cd build \ 
    && cmake .. -DCMAKE_INSTALL_PREFIX=/opt/gvm \ 
    && make \ 
    && make install
    
# python builds
RUN git clone -b ospd-20.08 --single-branch https://github.com/greenbone/ospd.git \
    && git clone -b ospd-openvas-20.08 --single-branch https://github.com/greenbone/ospd-openvas.git \
    && git clone -b v20.10.1 https://github.com/greenbone/gvm-tools.git \
    && mkdir -p $PYTHONPATH \
    && pip3 install --upgrade pip --target $PYTHONPATH \
    && pip3 install setuptools-rust --target $PYTHONPATH \
    && cd /tmp/gvm-source/ospd \ 
    && python3 setup.py install --prefix=/opt/gvm/ \
    && cd /tmp/gvm-source/ospd-openvas \ 
    && python3 setup.py install --prefix=/opt/gvm/ \
    # http://blog.networktocode.com/post/upgrade-your-python-project-with-poetry/
    && cd /tmp/gvm-source/gvm-tools \ 
    && rm poetry.toml \
    && mkdir /opt/gvm/.venv \
    && pip3 install --user poetry \
    && poetry config virtualenvs.path /opt/gvm/.venv --local \
    && poetry install \
    # manager certs
    && /opt/gvm/bin/gvm-manage-certs -a  && mkdir /opt/gvm/postgres/

USER root

ADD --chown=gvm:www ./config/start_ospd_openvas.sh /opt/gvm/start_ospd_openvas.sh
ADD --chown=gvm:www ./config/create_config_gvm.sh /opt/gvm/create_config_gvm.sh
ADD --chown=gvm:www ./config/update_openvas.sh /opt/gvm/update_openvas.sh

COPY --chown=gvm:www ./security_tools/openvas/ /srv/www/htdocs/openvas/
COPY --chown=gvm:www ./security_tools/jobs/ /opt/gvm/jobs/
COPY --chown=gvm:www ./webissues-server-2.0.0/client/webservices.wsdl /srv/www/htdocs/openvas/
COPY --chown=gvm:www ./webissues-server-2.0.0/client/webservices.xsd /srv/www/htdocs/openvas/

# redis needed by openvas
RUN cp /tmp/gvm-source/openvas/config/redis-openvas.conf /etc/redis/ && mkdir /run/redis-openvas/ && chown redis:redis /run/redis-openvas/ && chmod 777 /run/redis-openvas/ \
    && sed -i "s/unixsocketperm 770/unixsocketperm 777/g" /etc/redis/redis-openvas.conf \
    && chown redis:redis /etc/redis/redis-openvas.conf \
    && echo "db_address = /run/redis-openvas/redis.sock" > /opt/gvm/etc/openvas/openvas.conf \
    && chown gvm:www /opt/gvm/etc/openvas/openvas.conf \
    && usermod -aG redis gvm \
    # make aware postgresql of gvm libs: https://github.com/greenbone/gvmd/blob/master/INSTALL.md
    && echo "/opt/gvm/lib" > /etc/ld.so.conf.d/gvm.conf && ldconfig \
    && chmod ug+x /opt/gvm/start_ospd_openvas.sh /opt/gvm/create_config_gvm.sh /opt/gvm/update_openvas.sh && chown gvm:postgres /run/postgresql \
    # to run gvm tools from shell_exec
    && echo "%www ALL=(gvm:www) NOPASSWD:ALL" >> /etc/sudoers

USER gvm

EXPOSE 1080
EXPOSE 10443
EXPOSE 9392

ENTRYPOINT ["/opt/gvm/start_ospd_openvas.sh"]
