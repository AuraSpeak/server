module github.com/auraspeak/server

go 1.25.1

require (
	github.com/auraspeak/protocol v0.0.0
	github.com/pion/dtls/v3 v3.0.10
	github.com/sirupsen/logrus v1.9.4
	gopkg.in/yaml.v2 v2.4.0
)

require (
	github.com/davecgh/go-spew v1.1.1 // indirect
	github.com/pmezard/go-difflib v1.0.0 // indirect
	github.com/stretchr/testify v1.11.1
	gopkg.in/yaml.v3 v3.0.1 // indirect
)

require (
	github.com/pion/logging v0.2.4 // indirect
	github.com/pion/transport/v4 v4.0.1 // indirect
	golang.org/x/crypto v0.32.0 // indirect
	golang.org/x/sys v0.29.0 // indirect
)

replace github.com/auraspeak/protocol => ../protocol
