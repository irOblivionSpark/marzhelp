# marzhelp
A management bot and web panel for [Marzban](https://github.com/Gozargah/Marzban).

## Telegram
Join the support channel: [@marzhelp](https://t.me/marzhelp)

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
- Footer branding:
  - `Made with love by OblivionSpark`
  - linked to: `https://github.com/iroblivionSpark`

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
  <img src="https://github.com/ppouria/marzhelp/blob/main/screenshots/Screenshot.png" alt="Screenshot" width="300"/>
  <img src="https://github.com/ppouria/marzhelp/blob/main/screenshots/screenshot2.jpg" alt="Screenshot" width="300"/>
  <img src="https://github.com/ppouria/marzhelp/blob/main/screenshots/screenshot3.png" alt="Screenshot" width="300"/>
</p>

## Donations
- TRX: `TGftLESDAeRncE7yMAHrTUCsixuUwPc6qp`
- USDT (BEP20): `0x413eb47C430a3eb0E4262f267C1AE020E0C7F84D`
- Bitcoin: `bc1qnmuuxraew34g806ewkepxrhgln4ult6z5vkj9l`
- ETH/BNB/MATIC (ERC20/BEP20): `0x413eb47C430a3eb0E4262f267C1AE020E0C7F84D`
- TON: `UQDNpA3SlFMorlrCJJcqQjix93ijJfhAwIxnbTwZTLiHZ0Xa`

## License
Published under [AGPL-3.0](./LICENSE).
