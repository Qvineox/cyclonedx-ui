package server

import sbom_v1 "github.com/Qvineox/cyclonedx-ui/gen/go/api/proto/sbom/v1"

type Services struct {
	Sbom sbom_v1.SbomServiceServer
}
