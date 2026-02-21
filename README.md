# marzhelp
A management bot and web panel for [Marzban](https://github.com/Gozargah/Marzban).

## Telegram
Join the support channel: [@OblivionServer](https://t.me/OblivionServer)

## What Is Included
- Telegram bot for admin management
- Web panel for admin login and usage visibility
- Cron-based monitoring and automation
- MySQL-backed state and settings storage

## Main Features
- Create and modify admin accounts
- Admin restrictions and safety controls
- Enable or disable users, protocols, and inbounds by policy
- Track usage and remaining quota
- Store deleted and reset traffic history
- Show per-admin stats in bot and web panel

## Web Panel
The web panel is in `panel/` and runs next to the bot.

- URL: `https://your-domain:88/marzhelp/panel/`
- Login: Marzban admin `username` and `password`
- Dashboard:
  - used, total, and remaining traffic
  - users stats (total, active, expired, online)
  - limits and status view

## Installation
### Easy Installer (Recommended)
This installer is focused on servers where Marzban and MySQL are already running in Docker.
It asks for Telegram token/admin IDs and automatically sets the webhook.

```bash
bash <(curl -fsSL https://raw.githubusercontent.com/irOblivionSpark/marzhelp/main/install-easy.sh)
```

## Notes
- Port `80` is used to obtain Let's Encrypt SSL.
- After SSL setup, the project is served on port `88`.
- Webhook endpoint:
  - `https://your-domain:88/marzhelp/webhook.php`

## Screenshots
<p align="center">
  <img src="https://github.com/iroblivionspark/marzhelp/blob/main/screenshots/screenshot1.png" alt="Screenshot" width="300"/>
  <img src="https://github.com/iroblivionspark/marzhelp/blob/main/screenshots/screenshot2.png" alt="Screenshot" width="300"/>
  <img src="https://github.com/iroblivionspark/marzhelp/blob/main/screenshots/screenshot3.png" alt="Screenshot" width="300"/>
</p>

## Donations
Soon

## License
Published under [AGPL-3.0](./LICENSE).
