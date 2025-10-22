package server

import (
	project_v1 "github.com/Qvineox/cyclonedx-ui/gen/go/api/proto/project/v1"
	sbom_v1 "github.com/Qvineox/cyclonedx-ui/gen/go/api/proto/sbom/v1"
)

type Services struct {
	Sbom    sbom_v1.SbomServiceServer
	Project project_v1.ProjectServiceServer
}
