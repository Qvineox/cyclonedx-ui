package test

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	sbom_v1 "github.com/Qvineox/cyclonedx-ui/gen/go/api/proto/sbom/v1"
	"github.com/Qvineox/cyclonedx-ui/internal/services"
	"github.com/stretchr/testify/require"
)

const file = "trivy_sbom_report.cdx.json"

//const file = "cdxgen_fs_sbom.cdx.json"

func TestBehavior(t *testing.T) {
	s := services.NewSBOMServiceImpl()

	testFile, err := os.ReadFile(filepath.Join("examples", file))
	require.NoError(t, err)
	require.NotNil(t, testFile)

	t.Run("file decomposition with dependency cycles", func(t *testing.T) {
		decompose, err := s.Decompose(context.Background(), &sbom_v1.SBOMFile{
			FileName: file,
			Data:     testFile,
		})

		require.NotNil(t, decompose)
		require.NoError(t, err)
	})

}
