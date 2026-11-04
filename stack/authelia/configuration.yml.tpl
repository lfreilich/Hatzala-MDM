# Rendered by install.sh -> configuration.yml
theme: auto
server:
  address: 'tcp://127.0.0.1:9091/'
log:
  level: info
totp:
  issuer: '__DOMAIN__'
identity_validation:
  reset_password:
    jwt_secret: '__AUTHELIA_JWT_SECRET__'
authentication_backend:
  password_reset:
    disable: true
  file:
    path: /config/users_database.yml
    password:
      algorithm: argon2
access_control:
  default_policy: deny
  rules:
    - domain: ['__DOMAIN__', '*.__DOMAIN__']
      policy: two_factor
session:
  secret: '__AUTHELIA_SESSION_SECRET__'
  expiration: 12h
  inactivity: 2h
  cookies:
    - domain: '__DOMAIN__'
      authelia_url: 'https://auth.__DOMAIN__'
      default_redirection_url: 'https://__DOMAIN__'
regulation:
  max_retries: 5
  find_time: 10m
  ban_time: 30m
storage:
  encryption_key: '__AUTHELIA_STORAGE_KEY__'
  local:
    path: /config/db.sqlite3
notifier:
  # One-time codes for enrolling the authenticator app are written here.
  # Read them with:  hbs-addons 2fa-code
  filesystem:
    filename: /config/notification.txt
