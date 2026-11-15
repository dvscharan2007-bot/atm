Northgate ATM - Gender Field Update

Changes:
- Added a required Gender dropdown to the account registration form.
- Supported options: Male, Female, Other, Prefer not to say.
- Saves gender in the accounts table.
- Displays gender on the customer dashboard and admin account list.
- Existing SQLite and PostgreSQL databases are migrated automatically when the app starts.
- Existing accounts receive the value "Not specified"; their balances, cards, PIN hashes,
  and transaction history are not changed.

Deploy:
1. Replace the corresponding project files with these updated files.
2. Keep your existing environment variables and database connection settings.
3. Deploy/restart the Flask app. The database migration runs during app startup.
