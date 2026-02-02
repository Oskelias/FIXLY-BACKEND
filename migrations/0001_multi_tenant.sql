PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS tenants (
  id TEXT PRIMARY KEY,
  nombre TEXT NOT NULL,
  status TEXT DEFAULT 'active',
  plan TEXT DEFAULT 'free',
  created_at TEXT DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS locations (
  id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL,
  nombre TEXT NOT NULL,
  direccion TEXT DEFAULT '',
  telefono TEXT DEFAULT '',
  created_at TEXT DEFAULT (datetime('now')),
  FOREIGN KEY (tenant_id) REFERENCES tenants(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS users (
  id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL,
  location_id TEXT,
  username TEXT NOT NULL,
  email TEXT DEFAULT '',
  password TEXT NOT NULL,
  role TEXT DEFAULT 'user',
  plan TEXT DEFAULT 'free',
  status TEXT DEFAULT 'active',
  trial_ends_at TEXT,
  created_at TEXT DEFAULT (datetime('now')),
  last_login TEXT,
  FOREIGN KEY (tenant_id) REFERENCES tenants(id) ON DELETE CASCADE,
  FOREIGN KEY (location_id) REFERENCES locations(id) ON DELETE SET NULL,
  UNIQUE (tenant_id, username)
);

CREATE TABLE IF NOT EXISTS user_sessions (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id TEXT NOT NULL,
  tenant_id TEXT NOT NULL,
  device_id TEXT NOT NULL,
  token_hash TEXT NOT NULL,
  expires_at TEXT NOT NULL,
  device_name TEXT DEFAULT '',
  ip_address TEXT DEFAULT '',
  user_agent TEXT DEFAULT '',
  last_activity TEXT,
  created_at TEXT DEFAULT (datetime('now')),
  FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
  FOREIGN KEY (tenant_id) REFERENCES tenants(id) ON DELETE CASCADE,
  UNIQUE (user_id, tenant_id, device_id)
);

CREATE TABLE IF NOT EXISTS clientes (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  tenant_id TEXT NOT NULL,
  location_id TEXT NOT NULL,
  nombre TEXT NOT NULL,
  telefono TEXT DEFAULT '',
  email TEXT DEFAULT '',
  direccion TEXT DEFAULT '',
  created_at TEXT DEFAULT (datetime('now')),
  updated_at TEXT,
  FOREIGN KEY (tenant_id) REFERENCES tenants(id) ON DELETE CASCADE,
  FOREIGN KEY (location_id) REFERENCES locations(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS tecnicos (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  tenant_id TEXT NOT NULL,
  location_id TEXT NOT NULL,
  nombre TEXT NOT NULL,
  telefono TEXT DEFAULT '',
  email TEXT DEFAULT '',
  especialidad TEXT DEFAULT '',
  estado TEXT DEFAULT 'activo',
  created_at TEXT DEFAULT (datetime('now')),
  updated_at TEXT,
  FOREIGN KEY (tenant_id) REFERENCES tenants(id) ON DELETE CASCADE,
  FOREIGN KEY (location_id) REFERENCES locations(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS reparaciones (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  tenant_id TEXT NOT NULL,
  location_id TEXT NOT NULL,
  orden_id TEXT NOT NULL,
  cliente TEXT NOT NULL,
  telefono TEXT DEFAULT '',
  equipo TEXT NOT NULL,
  problema TEXT DEFAULT '',
  estado TEXT DEFAULT 'recibido',
  tecnico TEXT DEFAULT '',
  costo REAL DEFAULT 0,
  anticipo REAL DEFAULT 0,
  observaciones TEXT DEFAULT '',
  created_at TEXT DEFAULT (datetime('now')),
  updated_at TEXT,
  FOREIGN KEY (tenant_id) REFERENCES tenants(id) ON DELETE CASCADE,
  FOREIGN KEY (location_id) REFERENCES locations(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS pedidos (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  tenant_id TEXT NOT NULL,
  location_id TEXT NOT NULL,
  cliente TEXT NOT NULL,
  telefono TEXT DEFAULT '',
  producto TEXT NOT NULL,
  descripcion TEXT DEFAULT '',
  precio_total REAL DEFAULT 0,
  sena REAL DEFAULT 0,
  estado TEXT DEFAULT 'pendiente',
  created_at TEXT DEFAULT (datetime('now')),
  updated_at TEXT,
  FOREIGN KEY (tenant_id) REFERENCES tenants(id) ON DELETE CASCADE,
  FOREIGN KEY (location_id) REFERENCES locations(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS historial (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  tenant_id TEXT NOT NULL,
  location_id TEXT NOT NULL,
  referencia_tipo TEXT NOT NULL,
  referencia_id TEXT NOT NULL,
  descripcion TEXT NOT NULL,
  created_at TEXT DEFAULT (datetime('now')),
  FOREIGN KEY (tenant_id) REFERENCES tenants(id) ON DELETE CASCADE,
  FOREIGN KEY (location_id) REFERENCES locations(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_locations_tenant ON locations (tenant_id);
CREATE INDEX IF NOT EXISTS idx_users_tenant ON users (tenant_id);
CREATE INDEX IF NOT EXISTS idx_clientes_tenant_location ON clientes (tenant_id, location_id);
CREATE INDEX IF NOT EXISTS idx_tecnicos_tenant_location ON tecnicos (tenant_id, location_id);
CREATE INDEX IF NOT EXISTS idx_reparaciones_tenant_location ON reparaciones (tenant_id, location_id);
CREATE INDEX IF NOT EXISTS idx_pedidos_tenant_location ON pedidos (tenant_id, location_id);
CREATE INDEX IF NOT EXISTS idx_historial_tenant_location ON historial (tenant_id, location_id);
