CREATE TABLE IF NOT EXISTS clients (id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL, phone TEXT NOT NULL, email TEXT, city TEXT, address TEXT, dog_name TEXT, dog_breed TEXT, dog_birth TEXT, dog_notes TEXT, health_notes TEXT, consent INTEGER NOT NULL DEFAULT 0, notes TEXT, created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP, updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP);
CREATE TABLE IF NOT EXISTS bookings (id INTEGER PRIMARY KEY AUTOINCREMENT, reference TEXT UNIQUE NOT NULL, client_id INTEGER NOT NULL REFERENCES clients(id), service TEXT NOT NULL, service_key TEXT NOT NULL DEFAULT 'bilan', duration_minutes INTEGER NOT NULL DEFAULT 60, booking_date TEXT NOT NULL, booking_time TEXT NOT NULL, status TEXT NOT NULL DEFAULT 'pending' CHECK(status IN ('pending','confirmed','rejected','cancelled','completed')), notes TEXT, created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP, updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP);
CREATE INDEX IF NOT EXISTS bookings_date_idx ON bookings(booking_date,booking_time);
CREATE INDEX IF NOT EXISTS bookings_client_idx ON bookings(client_id);

CREATE TABLE IF NOT EXISTS login_attempts (ip_hash TEXT PRIMARY KEY, failures INTEGER NOT NULL DEFAULT 0, locked_until INTEGER NOT NULL DEFAULT 0);
CREATE TABLE IF NOT EXISTS blocked_times (id INTEGER PRIMARY KEY AUTOINCREMENT, starts_at TEXT NOT NULL, ends_at TEXT NOT NULL, reason TEXT);
