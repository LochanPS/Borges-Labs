module github.com/trust-infra/authorize-svc

go 1.23.0

require (
	github.com/jackc/pgx/v5 v5.7.1
	github.com/redis/go-redis/v9 v9.7.0
	github.com/santhosh-tekuri/jsonschema/v5 v5.3.1
	github.com/trust-infra/contracts/gen/go v0.0.0
)

require (
	github.com/cespare/xxhash/v2 v2.2.0 // indirect
	github.com/dgryski/go-rendezvous v0.0.0-20200823014737-9f7001d12a5f // indirect
	github.com/gowebpki/jcs v1.0.1 // indirect
	github.com/jackc/pgpassfile v1.0.0 // indirect
	github.com/jackc/pgservicefile v0.0.0-20240606120523-5a60cdf6a761 // indirect
	github.com/jackc/puddle/v2 v2.2.2 // indirect
	golang.org/x/crypto v0.27.0 // indirect
	golang.org/x/sync v0.8.0 // indirect
	golang.org/x/text v0.18.0 // indirect
)

// The frozen contract Go types live in-repo; bind them by local path so the
// service and the SDKs share one source of truth for the wire shape.
replace github.com/trust-infra/contracts/gen/go => ../../contracts/gen/go
