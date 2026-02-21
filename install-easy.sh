#!/usr/bin/env bash

set -euo pipefail

APP_DIR="/var/www/html/marzhelp"
CONFIG_FILE="/root/marzhelp.txt"
REPO_URL="https://github.com/irOblivionSpark/marzhelp.git"

BOT_TOKEN=""
ADMIN_IDS_CSV=""
BOT_DOMAIN=""
SERVER_IP=""
MYSQL_CONTAINER=""
MYSQL_ROOT_PASSWORD=""
MARZBAN_URL=""
MARZBAN_ADMIN_USERNAME=""
MARZBAN_ADMIN_PASSWORD=""
PHP_FPM_SOCKET=""

info() { echo -e "\033[1;34m[INFO]\033[0m $*"; }
ok() { echo -e "\033[1;32m[OK]\033[0m $*"; }
warn() { echo -e "\033[1;33m[WARN]\033[0m $*"; }
err() { echo -e "\033[1;31m[ERROR]\033[0m $*" >&2; }

ensure_root() {
    if [[ "$(id -u)" -ne 0 ]]; then
        err "Run this script as root."
        exit 1
    fi
}

require_command() {
    local cmd="$1"
    if ! command -v "${cmd}" >/dev/null 2>&1; then
        err "Required command not found: ${cmd}"
        exit 1
    fi
}

trim() {
    local text="$*"
    text="${text#"${text%%[![:space:]]*}"}"
    text="${text%"${text##*[![:space:]]}"}"
    printf '%s' "${text}"
}

read_env_variable() {
    local var_name="$1"
    local env_file="$2"
    grep -E "^[[:space:]]*${var_name}=" "${env_file}" 2>/dev/null | grep -v '^[[:space:]]*#' | head -n1 | cut -d'=' -f2- | tr -d '"' | tr -d '\r'
}

read_config_value() {
    local key="$1"
    if [[ ! -f "${CONFIG_FILE}" ]]; then
        return 0
    fi

    grep -E "^${key}=" "${CONFIG_FILE}" | head -n1 | cut -d'=' -f2- | tr -d '\r'
}

escape_sed_replacement() {
    printf '%s' "$1" | sed -e 's/[\/&]/\\&/g'
}

upsert_config_value() {
    local key="$1"
    local value="$2"
    local escaped_value
    escaped_value="$(escape_sed_replacement "${value}")"

    touch "${CONFIG_FILE}"
    if grep -q "^${key}=" "${CONFIG_FILE}"; then
        sed -i "s|^${key}=.*|${key}=${escaped_value}|" "${CONFIG_FILE}"
    else
        echo "${key}=${value}" >> "${CONFIG_FILE}"
    fi
}

prompt_with_default() {
    local question="$1"
    local default_value="${2:-}"
    local answer=""

    if [[ -n "${default_value}" ]]; then
        read -r -p "${question} [${default_value}]: " answer
        answer="${answer:-${default_value}}"
    else
        read -r -p "${question}: " answer
    fi

    printf '%s' "$(trim "${answer}")"
}

prompt_required() {
    local question="$1"
    local default_value="${2:-}"
    local value=""

    while true; do
        value="$(prompt_with_default "${question}" "${default_value}")"
        if [[ -n "${value}" ]]; then
            printf '%s' "${value}"
            return 0
        fi
        err "This value cannot be empty."
    done
}

get_public_ip() {
    local ip=""
    ip="$(curl -fsSL https://api.ipify.org 2>/dev/null || true)"
    if [[ -z "${ip}" ]]; then
        ip="$(curl -fsSL http://checkip.amazonaws.com 2>/dev/null || true)"
    fi
    echo "$(trim "${ip}")"
}

detect_mysql_container() {
    local detected=""
    detected="$(docker ps --format '{{.Names}}' | grep -Ei 'mysql|mariadb' | head -n1 || true)"
    echo "$(trim "${detected}")"
}

validate_admin_ids() {
    local ids="$1"
    [[ "${ids}" =~ ^[0-9]+(,[0-9]+)*$ ]]
}

mysql_exec() {
    local sql="$1"
    docker exec "${MYSQL_CONTAINER}" mysql -uroot -p"${MYSQL_ROOT_PASSWORD}" -e "${sql}"
}

mysql_exec_db() {
    local db="$1"
    local sql="$2"
    docker exec "${MYSQL_CONTAINER}" mysql -uroot -p"${MYSQL_ROOT_PASSWORD}" -D "${db}" -e "${sql}"
}

set_php_fpm_socket() {
    local php_version=""
    php_version="$(php -r 'echo PHP_MAJOR_VERSION.".".PHP_MINOR_VERSION;')"

    if [[ -S "/run/php/php${php_version}-fpm.sock" ]]; then
        PHP_FPM_SOCKET="/run/php/php${php_version}-fpm.sock"
    elif [[ -S "/var/run/php/php${php_version}-fpm.sock" ]]; then
        PHP_FPM_SOCKET="/var/run/php/php${php_version}-fpm.sock"
    else
        err "Could not find PHP-FPM socket for PHP ${php_version}."
        exit 1
    fi
}

load_defaults() {
    local domain_from_host=""
    local ip_from_public=""
    local token_from_config=""
    local admin_from_config=""
    local domain_from_config=""
    local ip_from_config=""
    local mysql_container_from_config=""
    local mysql_root_from_config=""
    local mysql_root_from_env=""
    local marzban_url_from_config=""
    local marzban_user_from_config=""
    local marzban_pass_from_config=""
    local mysql_container_detected=""

    domain_from_host="$(hostname -f 2>/dev/null || true)"
    ip_from_public="$(get_public_ip)"
    token_from_config="$(read_config_value "bot-api")"
    admin_from_config="$(read_config_value "admin-id")"
    domain_from_config="$(read_config_value "domain")"
    ip_from_config="$(read_config_value "ip")"
    mysql_container_from_config="$(read_config_value "mysql-container")"
    mysql_root_from_config="$(read_config_value "MYSQL_ROOT_PASSWORD")"
    marzban_url_from_config="$(read_config_value "marzban-url")"
    marzban_user_from_config="$(read_config_value "marzban-admin-username")"
    marzban_pass_from_config="$(read_config_value "marzban-admin-password")"

    mysql_container_detected="$(detect_mysql_container)"
    MYSQL_CONTAINER="${mysql_container_from_config:-${mysql_container_detected}}"

    if [[ -n "${MYSQL_CONTAINER}" ]]; then
        mysql_root_from_env="$(docker inspect "${MYSQL_CONTAINER}" --format '{{range .Config.Env}}{{println .}}{{end}}' | grep '^MYSQL_ROOT_PASSWORD=' | head -n1 | cut -d'=' -f2- || true)"
    fi

    if [[ -z "${mysql_root_from_env}" && -f /opt/marzban/.env ]]; then
        mysql_root_from_env="$(read_env_variable "MYSQL_ROOT_PASSWORD" "/opt/marzban/.env")"
    fi

    BOT_TOKEN="${token_from_config}"
    ADMIN_IDS_CSV="${admin_from_config}"
    BOT_DOMAIN="${domain_from_config:-${domain_from_host}}"
    SERVER_IP="${ip_from_config:-${ip_from_public}}"
    MYSQL_ROOT_PASSWORD="${mysql_root_from_config:-${mysql_root_from_env}}"
    MARZBAN_URL="${marzban_url_from_config:-http://127.0.0.1:8000}"
    MARZBAN_ADMIN_USERNAME="${marzban_user_from_config:-your_admin_username}"
    MARZBAN_ADMIN_PASSWORD="${marzban_pass_from_config:-your_admin_password}"
}

collect_inputs() {
    info "Collecting configuration values..."

    BOT_TOKEN="$(prompt_required "Telegram Bot Token" "${BOT_TOKEN}")"
    ADMIN_IDS_CSV="$(prompt_required "Telegram admin ID(s), comma separated (example: 123456,789012)" "${ADMIN_IDS_CSV}")"
    if ! validate_admin_ids "${ADMIN_IDS_CSV}"; then
        err "Invalid admin IDs format. Use only numbers and commas."
        exit 1
    fi

    BOT_DOMAIN="$(prompt_required "Domain for Marzhelp (DNS must point to this server)" "${BOT_DOMAIN}")"
    SERVER_IP="$(prompt_required "Server public IP" "${SERVER_IP}")"

    MYSQL_CONTAINER="$(prompt_required "Docker MySQL container name" "${MYSQL_CONTAINER}")"
    if ! docker ps --format '{{.Names}}' | grep -Fxq "${MYSQL_CONTAINER}"; then
        err "Container not found or not running: ${MYSQL_CONTAINER}"
        exit 1
    fi

    if [[ -z "${MYSQL_ROOT_PASSWORD}" ]]; then
        MYSQL_ROOT_PASSWORD="$(prompt_required "MySQL root password (inside Docker container)")"
    else
        MYSQL_ROOT_PASSWORD="$(prompt_required "MySQL root password (inside Docker container)" "${MYSQL_ROOT_PASSWORD}")"
    fi

    MARZBAN_URL="$(prompt_required "Marzban panel URL" "${MARZBAN_URL}")"
    MARZBAN_ADMIN_USERNAME="$(prompt_with_default "Marzban admin username (optional)" "${MARZBAN_ADMIN_USERNAME}")"
    MARZBAN_ADMIN_PASSWORD="$(prompt_with_default "Marzban admin password (optional)" "${MARZBAN_ADMIN_PASSWORD}")"

    if [[ -z "${MARZBAN_ADMIN_USERNAME}" ]]; then
        MARZBAN_ADMIN_USERNAME="your_admin_username"
    fi
    if [[ -z "${MARZBAN_ADMIN_PASSWORD}" ]]; then
        MARZBAN_ADMIN_PASSWORD="your_admin_password"
    fi
}

install_packages() {
    info "Installing dependencies (without MySQL server package)..."
    export DEBIAN_FRONTEND=noninteractive
    apt-get update -y
    apt-get install -y nginx php php-cli php-fpm php-curl php-mbstring php-xml php-zip php-soap php-mysql git wget unzip curl certbot python3-certbot-nginx ufw

    if dpkg -l | grep -q '^ii  apache2'; then
        warn "Removing Apache to avoid port conflicts..."
        systemctl stop apache2 2>/dev/null || true
        systemctl disable apache2 2>/dev/null || true
        apt-get purge -y apache2 apache2-bin apache2-data apache2-utils libapache2-mod-php8.1 || true
        apt-get autoremove -y || true
    fi

    systemctl enable --now php8.1-fpm nginx
    set_php_fpm_socket
}

configure_firewall() {
    if command -v ufw >/dev/null 2>&1; then
        info "Opening firewall ports 80 and 88 (if UFW is enabled)..."
        ufw allow 80/tcp >/dev/null 2>&1 || true
        ufw allow 88/tcp >/dev/null 2>&1 || true
    fi
}

prepare_project() {
    info "Deploying project to ${APP_DIR}..."
    rm -rf "${APP_DIR}"
    git clone "${REPO_URL}" "${APP_DIR}"
    chown -R www-data:www-data "${APP_DIR}"
    chmod -R 755 "${APP_DIR}"
}

configure_permissions() {
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

setup_database() {
    info "Creating marzhelp database and required tables in Docker MySQL..."
    mysql_exec "CREATE DATABASE IF NOT EXISTS marzhelp;"
    mysql_exec_db "marzban" "CREATE TABLE IF NOT EXISTS user_deletions (user_id int DEFAULT NULL, admin_id int DEFAULT NULL, deleted_at timestamp NULL DEFAULT CURRENT_TIMESTAMP, used_traffic bigint DEFAULT NULL, reseted_usage bigint DEFAULT NULL);"
}

write_config_php() {
    info "Writing ${APP_DIR}/config.php..."
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
    if [[ ! -f "/etc/letsencrypt/live/${BOT_DOMAIN}/fullchain.pem" ]]; then
        info "Issuing SSL certificate for ${BOT_DOMAIN}..."
        certbot certonly --nginx --non-interactive --agree-tos --register-unsafely-without-email -d "${BOT_DOMAIN}"
    else
        local renew_choice=""
        renew_choice="$(prompt_with_default "SSL certificate exists for ${BOT_DOMAIN}. Renew now? (y/n)" "n")"
        if [[ "${renew_choice}" =~ ^[Yy]$ ]]; then
            info "Renewing SSL certificate for ${BOT_DOMAIN}..."
            certbot renew --cert-name "${BOT_DOMAIN}" || true
        else
            info "Reusing current SSL certificate for ${BOT_DOMAIN}."
        fi
    fi

    info "Configuring Nginx on ports 80 and 88..."
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
        fastcgi_pass unix:${PHP_FPM_SOCKET};
    }
}
NGINX

    ln -sf /etc/nginx/sites-available/marzhelp /etc/nginx/sites-enabled/marzhelp
    rm -f /etc/nginx/sites-enabled/default
    nginx -t
    systemctl restart nginx php8.1-fpm
}

run_table_setup() {
    info "Running table.php..."
    php "${APP_DIR}/table.php"
}

set_telegram_webhook() {
    local delete_response=""
    local set_response=""
    local info_response=""

    info "Setting Telegram webhook..."
    delete_response="$(curl -fsSL "https://api.telegram.org/bot${BOT_TOKEN}/deleteWebhook")"
    set_response="$(curl -fsSL "https://api.telegram.org/bot${BOT_TOKEN}/setWebhook?url=https://${BOT_DOMAIN}:88/marzhelp/webhook.php&ip_address=${SERVER_IP}&max_connections=40")"
    info_response="$(curl -fsSL "https://api.telegram.org/bot${BOT_TOKEN}/getWebhookInfo")"

    if ! echo "${set_response}" | grep -q '"ok":true'; then
        err "Webhook setup failed. Telegram response: ${set_response}"
        exit 1
    fi

    ok "Webhook configured successfully."
    echo "deleteWebhook: ${delete_response}"
    echo "setWebhook: ${set_response}"
    echo "getWebhookInfo: ${info_response}"
}

save_config_state() {
    info "Saving installer values to ${CONFIG_FILE}..."
    upsert_config_value "MYSQL_ROOT_PASSWORD" "${MYSQL_ROOT_PASSWORD}"
    upsert_config_value "bot-api" "${BOT_TOKEN}"
    upsert_config_value "admin-id" "${ADMIN_IDS_CSV}"
    upsert_config_value "domain" "${BOT_DOMAIN}"
    upsert_config_value "ip" "${SERVER_IP}"
    upsert_config_value "allowed_users" "${ADMIN_IDS_CSV}"
    upsert_config_value "mysql-container" "${MYSQL_CONTAINER}"
    upsert_config_value "marzban-url" "${MARZBAN_URL}"
    upsert_config_value "marzban-admin-username" "${MARZBAN_ADMIN_USERNAME}"
    upsert_config_value "marzban-admin-password" "${MARZBAN_ADMIN_PASSWORD}"
}

main() {
    ensure_root
    require_command docker

    load_defaults
    collect_inputs

    install_packages
    configure_firewall
    prepare_project
    configure_permissions
    setup_database
    write_config_php
    configure_nginx_ssl
    run_table_setup
    set_telegram_webhook
    save_config_state

    ok "Installation completed."
    echo "Webhook:   https://${BOT_DOMAIN}:88/marzhelp/webhook.php"
    echo "Web Panel: https://${BOT_DOMAIN}:88/marzhelp/panel/"
}

main "$@"
