#!/bin/bash

docker compose run --rm chatwoot bundle exec rails db:chatwoot_prepare

docker compose exec odoo odoo -d odoo_db -i base --without-demo=all --stop-after-init \
  --db_host=postgres \
  --db_port=5432 \
  --db_user=postgresadmin \
  --db_password=postgresSUPERpasswd