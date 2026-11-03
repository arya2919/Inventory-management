# StockFlow MVP

A compact, single-owner inventory workspace built from the StockFlow Phase 1 PRD. It includes email/password signup, an organization created for each account, product CRUD, inventory totals, low-stock monitoring, search, and a per-store default alert threshold.

## Run locally

Requires Node.js 20 or newer. SQLite creates itself on first launch.

```sh
npm install
cp .env.example .env
npm run dev
```

Open [http://localhost:3000](http://localhost:3000). Create a store and owner account from the signup screen. Each account can only read and change products belonging to its organization. Passwords are hashed with bcrypt, sessions use SQLite, and form writes are protected by a per-session CSRF token.

## Deploy

The repository includes a Render Blueprint at [`render.yaml`](render.yaml). It defines a Node web service and a persistent disk for the SQLite database. Connect the GitHub repository to Render and deploy the Blueprint from the Render dashboard. The Starter web service and persistent disk are paid Render resources; review the current cost in Render before deploying. Render documents the Blueprint flow at [render.com/docs/infrastructure-as-code](https://render.com/docs/infrastructure-as-code).

For another host, set `NODE_ENV=production`, provide a long random `SESSION_SECRET`, point `DATABASE_PATH` at durable storage, run `npm install`, and start with `npm start`. The app must run as a single instance while using SQLite.

## MVP boundaries

- One owner per organization; no invites or staff roles.
- No password recovery, stock movement ledger, imports, integrations, warehouses, orders, or billing.
- SQLite is a practical demo database, not a multi-instance production datastore.
- The default threshold starts at 5 units and can be changed in Settings. A product-specific threshold overrides it.
- Price display uses INR for the demo; currency selection is outside this MVP.
