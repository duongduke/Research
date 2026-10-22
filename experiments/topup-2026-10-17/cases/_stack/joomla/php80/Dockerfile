# Joomla 4.2.x web image (lab only)
# Base: official PHP 8.0 + Apache, pinned by digest (Joomla 4.2 supports PHP 7.2.5–8.0).
# mysqli is the only extra extension the Joomla installer needs; rewrite is enabled for
# completeness (the API is reached as /api/index.php/... and does not require it).
FROM php:8.0-apache@sha256:c87b4c94d53b35520467b6d026f38656ab9a6d446fa3a0fbba1bc633125f9ad2
RUN docker-php-ext-install mysqli && a2enmod rewrite
