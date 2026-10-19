# NKN SocialUp Full Panel Starter

Files:
- `index.html`: responsive dark-purple customer/admin UI.
- `database_setup.sql`: wallet table, auth profile/wallet trigger, secure RPCs and policies.

## Important
This is a starter build, not a fully audited production release. Before public use, test every flow with separate customer and admin accounts. Review RLS and SQL in your existing Supabase project before running it. Your project already has tables from earlier setup, so this script assumes those tables/columns exist as previously created:
`profiles`, `services`, `orders`, `deposit_requests`, `wallet_transactions`, `user_roles`.

## Setup
1. Run `database_setup.sql` in Supabase SQL Editor after reviewing it.
2. Keep the Supabase Publishable key in the HTML; never put a `service_role` or secret key in browser code.
3. Register a normal account.
4. In Supabase Authentication > Users, copy your account UUID.
5. In SQL Editor, set that account as admin using the commented SQL at the end of `database_setup.sql`.
6. Add services from Admin Panel.
7. Configure email confirmation and your Supabase Auth redirect URLs as appropriate.

## Limits / manual workflow
- Payments are NOT automatically detected. Admin must verify bKash/Nagad payment and approve requests.
- Orders are recorded and charged from the wallet; actual delivery is manual. This starter does not connect to an external SMM provider.
- No real payment gateway is integrated.
- Verify all existing table column names and constraints before running SQL. Database schema changes should be backed up first.
