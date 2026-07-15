package backend

// PostgresUserConfig holds per-user postgres settings.
type PostgresUserConfig struct {
	ConnectionString string `yaml:"connection_string"`
	TableName        string `yaml:"table_name"`
}

// PostgresBackendConfig holds global postgres defaults.
type PostgresBackendConfig struct {
	DefaultConnectionString string `yaml:"default_connection_string"`
}
