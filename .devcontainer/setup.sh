#!/bin/bash
set -x

echo "Setting up Passman development environment..."

while [ ! -d /var/www/html/lib ]; do
  echo "Waiting for Nextcloud files to be available..."
  sleep 1
done

git config --global --add safe.directory /var/www/html/custom_apps/passman

# chown -R www-data:www-data /var/www/html/custom_apps
php /var/www/html/occ maintenance:install \
    --verbose \
    --database=mysql \
    --database-name=nextcloud \
    --database-host=db \
    --database-pass=nextcloud \
    --database-user=nextcloud \
    --admin-user=admin \
    --admin-pass=admin

php /var/www/html/occ app:enable passman
php /var/www/html/occ config:system:set defaultapp --value=passman
php /var/www/html/occ config:system:set appstoreenabled --value=false
