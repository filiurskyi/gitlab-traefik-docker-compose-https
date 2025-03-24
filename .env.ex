# Traefik Variables
TRAEFIK_IMAGE_TAG=traefik:latest
# Set the log level (DEBUG, INFO, WARN, ERROR)
TRAEFIK_LOG_LEVEL=WARN
# The email address used by Let's Encrypt for renewal notices
TRAEFIK_ACME_EMAIL=admin@example.com
# The hostname used to access the Traefik dashboard and to configure domain-specific rules
TRAEFIK_HOSTNAME=traefik.gitlab.<mydomain>.net
# Basic Authentication for Traefik Dashboard
# Username: traefikadmin
# Passwords must be encoded using MD5, SHA1, or BCrypt
TRAEFIK_BASIC_AUTH=<traefik_admin_username>:<pw_hash>

# GitLab Variables
GITLAB_POSTGRES_IMAGE_TAG=postgres:latest
GITLAB_IMAGE_TAG=gitlab/gitlab-ee:latest
GITLAB_RUNNER_IMAGE_TAG=gitlab/gitlab-runner:latest
GITLAB_DB_TYPE=postgresql
GITLAB_DB_NAME=gitlabhq_production
GITLAB_DB_USER=gitlab
GITLAB_DB_PASSWORD=<set_this>
GITLAB_URL=https://git.<mydomain>.<com>
GITLAB_HOSTNAME=git.<mydomain>.<com>
GITLAB_SHELL_SSH_PORT=<custom_port>
GITLAB_SMTP_ADDRESS=smtp.<your_email_provider>.com
GITLAB_SMTP_USER_NAME=gitlab@<mydomain>.<com>
GITLAB_SMTP_PASSWORD=<set_this>
GITLAB_EMAIL_FROM=gitlab@<mydomain>.<com>
GITLAB_EMAIL_REPLY_TO=gitlab@<mydomain>.<com>
