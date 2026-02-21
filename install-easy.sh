#!/usr/bin/env bash

set -euo pipefail

APP_DIR="/var/www/html/marzhelp"
DOMAIN_DEFAULT=""
IP_DEFAULT=""
MYSQL_CONTAINER_DEFAULT=""
MZB_CONTAINER_DEFAULT=""

red() { echo -e "\033[1;31m$*\033[0m"; }
green() { echo -e "\033[1;32m$*\033[0m"; }
blue() { echo -e "\033[1;34m$*\033[0m"; }
yellow() { echo -e "\033[1;33m$*\033[0m"; }

require_root() {
    if [[ "${EUID}" -ne 0 ]]; then
        red "Run this script as root."
        exit 1
    fi
}

detect_defaults() {
    DOMAIN_DEFAULT="$(hostname -f 2>/dev/null || true)"
    IP_DEFAULT="$(curl -fsSL https://api.ipify.org 2>/dev/null || true)"

    MYSQL_CONTAINER_DEFAULT="$(docker ps --format '{{.Names}}' | grep -Ei 'mysql' | head -n1 || true)"
    MZB_CONTAINER_DEFAULT="$(docker ps --format '{{.Names}}' | grep -Ei 'marzban' | head -n1 || true)"
}

prompt_input() {
    local prompt="$1"
    local default_value="${2:-}"
    local value=""
    if [[ -n "${default_value}" ]]; then
        read -r -p "${prompt} [${default_value}]: " value
        value="${value:-${default_value}}"
    else
        read -r -p "${prompt}: " value
    fi
    echo "${value}"
}

install_packages() {
    blue "Installing dependencies (no MySQL server package)..."
    export DEBIAN_FRONTEND=noninteractive
    apt-get update -y
    apt-get install -y nginx php php-cli php-fpm php-curl php-mbstring php-xml php-zip php-soap php-mysql git wget unzip curl certbot python3-certbot-nginx

    if dpkg -l | grep -q "^ii  apache2"; then
        yellow "Removing Apache to avoid port conflicts..."
        systemctl stop apache2 2>/dev/null || true
        apt-get purge -y apache2 apache2-bin apache2-data apache2-utils libapache2-mod-php8.1 || true
        apt-get autoremove -y || true
    fi

    systemctl enable --now php8.1-fpm nginx
}

prepare_project() {
    blue "Deploying project files to ${APP_DIR}..."
    rm -rf "${APP_DIR}"
    git clone https://github.com/irOblivionSpark/marzhelp.git "${APP_DIR}"
    chown -R www-data:www-data "${APP_DIR}"
    chmod -R 755 "${APP_DIR}"

    chmod +x /usr/bin/crontab /usr/bin/wget || true
    if [[ -x /usr/local/bin/marzban ]]; then
        chmod +x /usr/local/bin/marzban || true
    fi

    {
        echo "www-data ALL=(ALL) NOPASSWD: /usr/bin/crontab"
        echo "www-data ALL=(ALL) NOPASSWD: /usr/bin/wget"
        if [[ -x /usr/local/bin/marzban ]]; then
            echo "www-data ALL=(ALL) NOPASSWD: /usr/local/bin/marzban"
        fi
    } | sort -u > /etc/sudoers.d/marzhelp
    chmod 440 /etc/sudoers.d/marzhelp
}

read_container_env() {
    local container="$1"
    local key="$2"
    docker inspect "${container}" --format '{{range .Config.Env}}{{println .}}{{end}}' | grep "^${key}=" | head -n1 | cut -d'=' -f2-
}

setup_database() {
    blue "Configuring databases inside Docker MySQL container..."
    docker exec "${MYSQL_CONTAINER}" mysql -uroot -p"${MYSQL_ROOT_PASSWORD}" -e "CREATE DATABASE IF NOT EXISTS marzhelp;"
    docker exec "${MYSQL_CONTAINER}" mysql -uroot -p"${MYSQL_ROOT_PASSWORD}" -D marzban -e "CREATE TABLE IF NOT EXISTS user_deletions (user_id int DEFAULT NULL, admin_id int DEFAULT NULL, deleted_at timestamp NULL DEFAULT CURRENT_TIMESTAMP, used_traffic bigint DEFAULT NULL, reseted_usage bigint DEFAULT NULL);"
}

write_config() {
    blue "Writing config.php..."
    cat > "${APP_DIR}/config.php" <<PHP
<?php
\$botToken = '${BOT_TOKEN}';
\$apiURL = "https://api.telegram.org/bot\$botToken/";
\$botdomain = '${BOT_DOMAIN}';

\$allowedUsers = [${ADMIN_IDS_CSV}];

\$botDbHost = '127.0.0.1';
\$botDbUser = 'root';
\$botDbPass = '${MYSQL_ROOT_PASSWORD}';
\$botDbName = 'marzhelp';

\$vpnDbHost = '127.0.0.1';
\$vpnDbUser = 'root';
\$vpnDbPass = '${MYSQL_ROOT_PASSWORD}';
\$vpnDbName = 'marzban';

\$marzbanUrl = '${MARZBAN_URL}';
\$marzbanAdminUsername = '${MARZBAN_ADMIN_USERNAME}';
\$marzbanAdminPassword = '${MARZBAN_ADMIN_PASSWORD}';
?>
PHP

    chown www-data:www-data "${APP_DIR}/config.php"
    chmod 640 "${APP_DIR}/config.php"
}

configure_nginx_ssl() {
    blue "Requesting SSL certificate for ${BOT_DOMAIN}..."
    certbot certonly --nginx --non-interactive --agree-tos --register-unsafely-without-email -d "${BOT_DOMAIN}"

    blue "Configuring Nginx (80 -> 88 + PHP-FPM)..."
    cat > /etc/nginx/sites-available/marzhelp <<NGINX
server {
    listen 80;
    listen [::]:80;
    server_name ${BOT_DOMAIN};

    location /.well-known/acme-challenge/ {
        root /var/www/html;
    }

    location / {
        return 301 https://\$host:88\$request_uri;
    }
}

server {
    listen 88 ssl;
    listen [::]:88 ssl;
    server_name ${BOT_DOMAIN};

    root /var/www/html;
    index index.php index.html index.htm;

    ssl_certificate /etc/letsencrypt/live/${BOT_DOMAIN}/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/${BOT_DOMAIN}/privkey.pem;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers HIGH:!aNULL:!MD5;

    location / {
        try_files \$uri \$uri/ =404;
    }

    location ~ \\.php$ {
        include snippets/fastcgi-php.conf;
        fastcgi_pass unix:/var/run/php/php8.1-fpm.sock;
    }
}
NGINX

    ln -sf /etc/nginx/sites-available/marzhelp /etc/nginx/sites-enabled/marzhelp
    rm -f /etc/nginx/sites-enabled/default
    nginx -t
    systemctl restart nginx php8.1-fpm
}

finalize_bot() {
    blue "Initializing Marzhelp tables and cron..."
    php "${APP_DIR}/table.php"

    blue "Setting Telegram webhook..."
    curl -fsSL "https://api.telegram.org/bot${BOT_TOKEN}/deleteWebhook" >/dev/null
    curl -fsSL "https://api.telegram.org/bot${BOT_TOKEN}/setWebhook?url=https://${BOT_DOMAIN}:88/marzhelp/webhook.php&ip_address=${SERVER_IP}&max_connections=40" >/dev/null

    cat > /root/marzhelp.txt <<EOF
MYSQL_ROOT_PASSWORD=${MYSQL_ROOT_PASSWORD}
bot-api=${BOT_TOKEN}
admin-id=${ADMIN_IDS_CSV}
domain=${BOT_DOMAIN}
ip=${SERVER_IP}
allowed_users=${ADMIN_IDS_CSV}
EOF
}

main() {
    require_root

    if ! command -v docker >/dev/null 2>&1; then
        red "Docker is required because this installer expects Marzban MySQL in a container."
        exit 1
    fi

    detect_defaults

    green "Marzhelp Easy Installer (Web Panel + Telegram Bot)"
    BOT_DOMAIN="$(prompt_input 'Domain (must point to this server)' "${DOMAIN_DEFAULT}")"
    SERVER_IP="$(prompt_input 'Server public IP' "${IP_DEFAULT}")"
    BOT_TOKEN="$(prompt_input 'Telegram Bot Token')"
    ADMIN_IDS_CSV="$(prompt_input 'Telegram admin ID(s), comma separated (example: 123,456)')"
    MYSQL_CONTAINER="$(prompt_input 'Docker MySQL container name' "${MYSQL_CONTAINER_DEFAULT}")"

    if [[ -z "${BOT_DOMAIN}" || -z "${SERVER_IP}" || -z "${BOT_TOKEN}" || -z "${ADMIN_IDS_CSV}" || -z "${MYSQL_CONTAINER}" ]]; then
        red "Domain, IP, bot token, admin IDs, and MySQL container are required."
        exit 1
    fi

    MYSQL_ROOT_PASSWORD="$(read_container_env "${MYSQL_CONTAINER}" "MYSQL_ROOT_PASSWORD")"
    if [[ -z "${MYSQL_ROOT_PASSWORD}" ]]; then
        red "Could not read MYSQL_ROOT_PASSWORD from container ${MYSQL_CONTAINER}."
        exit 1
    fi

    MARZBAN_URL="http://127.0.0.1:8000"
    MARZBAN_ADMIN_USERNAME="$(prompt_input 'Marzban admin username (for API features)')"
    MARZBAN_ADMIN_PASSWORD="$(prompt_input 'Marzban admin password (for API features)')"
    if [[ -z "${MARZBAN_ADMIN_USERNAME}" || -z "${MARZBAN_ADMIN_PASSWORD}" ]]; then
        red "Marzban admin username/password are required."
        exit 1
    fi

    install_packages
    prepare_project
    setup_database
    write_config
    configure_nginx_ssl
    finalize_bot

    green "Installation completed."
    echo "Bot webhook: https://${BOT_DOMAIN}:88/marzhelp/webhook.php"
    echo "Web panel:   https://${BOT_DOMAIN}:88/marzhelp/panel/"
}

main "$@"

