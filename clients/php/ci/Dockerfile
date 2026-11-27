# The image scripts/check.sh runs the PHP gate client in when the machine has no PHP 8.4+ with ext-sodium and Composer
# (the CI workflow client-php builds it too and runs clients/php/ci.sh inside, so the image is checked on every pull
# request). The newest stable PHP, pinned by digest; Dependabot (`docker`, /clients/php/ci) moves the pins.
FROM composer:2.11.2@sha256:cd3a90dc5624c59a2f9ddf80dad08569f06416db31de519024f249d63bca554b AS composer

FROM php:8.6.0-cli-trixie@sha256:d84acf3155d907afaa5afa9b9457c5f12016b6dc7ade84659f40cdc505cc087d
# unzip: Composer unpacks the dist archives with it (the image has no zip extension). mbstring: PHPUnit needs it, and
# the official 8.6 image no longer builds it in (the library itself does not use it). sodium, curl and json are part of
# the image.
RUN apt-get update \
    && apt-get install -y --no-install-recommends unzip libonig-dev \
    && docker-php-ext-install -j"$(nproc)" mbstring \
    && apt-get purge -y --auto-remove libonig-dev \
    && apt-get install -y --no-install-recommends libonig5 \
    && rm -rf /var/lib/apt/lists/*
COPY --from=composer /usr/bin/composer /usr/local/bin/composer
