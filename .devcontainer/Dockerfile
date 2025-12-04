ARG BASE_IMAGE

FROM ${BASE_IMAGE:-nextcloud:stable-apache} as base

RUN curl -fsSL https://deb.nodesource.com/setup_20.x | bash - && \
    apt install -y sudo nodejs git && \
    rm -rf /var/lib/apt/lists/* && \
    npm install -g sass grunt-cli

RUN usermod -s /bin/bash root
RUN usermod -s /bin/bash www-data

RUN php -r "copy('https://getcomposer.org/installer', 'composer-setup.php');" && \
    php composer-setup.php --install-dir=/usr/local/bin --filename=composer  && \
    php -r "unlink('composer-setup.php');"

