# Private SMS Inbox

A small, private, single-user web inbox for SMS delivered to a phone number **you own** through a supported SMS provider. This initial version supports Telnyx API v2 inbound SMS webhooks.

It does **not** generate telephone numbers, provide free phone numbers, receive messages without a real SMS-capable number, or bypass WhatsApp/account-verification restrictions.

## WhatsApp compatibility warning

WhatsApp requires a phone number you own and can verify. Its official help guidance lists VoIP numbers among unsupported number types (and lists landlines as supported only in WhatsApp Business). A provider number being able to receive ordinary SMS does not mean WhatsApp will send a registration code to it. Check the number type and WhatsApp eligibility **before paying**. This app cannot make an unsupported number acceptable.

## Requirements

- Node.js 22.13+ (Node 26 is suitable).
- A Telnyx account that has passed any required identity/business checks.
- A real SMS-capable number provisioned to you by Telnyx in a supported country.
- A publicly reachable HTTPS URL for the webhook. A VPS or a reliable HTTPS tunnel can provide this. A phone running Termux may sleep or lose connectivity, so it is not ideal as the always-on webhook host.

Number availability, permitted use, identity documents, local address requirements, and SMS capabilities vary by country. Telnyx may require regulatory documents before ordering a number. Do not use a number unless the provider has assigned it to you and permits your intended use.

## Install

```bash
cp .env.example .env
```

Edit `.env` and set:

- `DASHBOARD_USER`: your dashboard username.
- `DASHBOARD_PASSWORD`: a unique random password of at least 20 characters.
- `OWNED_NUMBER`: the exact number assigned to you, in E.164 format (for example `+12125550123`; example only).
- `TELNYX_PUBLIC_KEY`: the base64 Ed25519 webhook public key shown in Telnyx Mission Control under Account Settings / Keys & Credentials / Public Key.

Do not put a Telnyx API secret in this project. Do not commit `.env`, the database, screenshots of OTPs, or secrets to GitHub.

Start the server:

```bash
npm test
npm start
```

Open `http://127.0.0.1:3000` on the same device. The browser will ask for the username/password using HTTP Basic Authentication.

## Configure Telnyx inbound SMS

1. Obtain an SMS-capable number assigned to you. Verify its country, number type, inbound SMS support, regulatory requirements, and acceptable-use rules with Telnyx.
2. In Telnyx Mission Control, create or select a Messaging Profile.
3. Set its inbound webhook URL to `https://YOUR-HTTPS-HOST/webhooks/telnyx`.
4. Enable webhook signing and use the matching account public key in `TELNYX_PUBLIC_KEY`.
5. Associate only your assigned SMS number with the Messaging Profile.
6. Send a normal test SMS from a number you control. Confirm it appears in the private inbox.

Telnyx signs API v2 webhooks with Ed25519. This app verifies the signature over the **raw** request body and rejects timestamps older than five minutes. It also stores messages only when the `to` number exactly matches `OWNED_NUMBER`, deduplicates provider message IDs, and deletes messages after the configured retention period (default: 24 hours).

## Termux notes

If Node.js is already installed, check it with `node --version`. On Termux, run the project from its directory and keep the terminal session alive while testing. For reliable inbound delivery, host the webhook on an always-on VPS or a reliable HTTPS tunnel; do not expose port 3000 directly to the public internet.

## Security

- Single-user dashboard protected with HTTP Basic Authentication.
- Telnyx signature verification and five-minute replay window.
- Only the configured owned destination number is accepted.
- Duplicate message events are ignored.
- Messages expire automatically; manual inbox clearing is available.
- The app does not send SMS, initiate calls, or forward OTPs to other users.
- Use HTTPS for any public webhook and dashboard access. Never share the dashboard password.

## API routes

- `POST /webhooks/telnyx` — signed Telnyx inbound webhook (no browser auth; cryptographic signature required).
- `GET /api/messages` — list the latest 200 messages (Basic Auth).
- `DELETE /api/messages` — delete all stored messages (Basic Auth).
- `GET /` — private inbox dashboard (Basic Auth).

## Provider references

- [Telnyx: Receiving SMS on your Telnyx number](https://support.telnyx.com/en/articles/4348981-receiving-sms-on-your-telnyx-number)
- [Telnyx: Webhook signing and verification](https://support.telnyx.com/en/articles/4334722-how-to-leverage-webhooks)
- [Official Telnyx Node SDK webhook verification example](https://github.com/team-telnyx/telnyx-node/tree/master/examples/webhook-verification)
- [WhatsApp Help Center: Register your phone number](https://faq.whatsapp.com/684051319521343/)
