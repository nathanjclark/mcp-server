-- Change users.id from UUID to TEXT
ALTER TABLE users ALTER COLUMN id TYPE TEXT;

-- Change oauth_authorization_codes.user_id from UUID to TEXT
ALTER TABLE oauth_authorization_codes ALTER COLUMN user_id TYPE TEXT; 