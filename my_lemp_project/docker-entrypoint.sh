#!/bin/sh
set -e

# Wait for the database to be ready
until php -r "try { new PDO('mysql:host=db;dbname=my_database', 'my_user', 'my_password'); } catch (PDOException $e) { exit(1); }"; do
  >&2 echo "Database is unavailable - sleeping"
  sleep 1
done

>&2 echo "Database is up - executing command"

# Run installation if tables don't exist
if ! php -r "try { \$pdo = new PDO('mysql:host=db;dbname=my_database', 'my_user', 'my_password'); \$pdo->query('SELECT 1 FROM users LIMIT 1'); } catch (Exception \$e) { exit(1); }"; then
    echo "Running installation..."
    php /var/www/html/install.php
else
    echo "Tables already exist. Skipping installation."
fi

# Execute the CMD
exec "$@"
