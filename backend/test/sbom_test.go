package test

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/Qvineox/cyclonedx-ui/cfg"
	sbom_v1 "github.com/Qvineox/cyclonedx-ui/gen/go/api/proto/sbom/v1"
	"github.com/Qvineox/cyclonedx-ui/internal/services"
	"github.com/stretchr/testify/require"
)

const file = "sbom.cdx.json"

//const file = "cdxgen_fs_sbom.cdx.json"

func TestBehavior(t *testing.T) {
	var minSeverity = 1.0
	s := services.NewSBOMServiceImpl(cfg.CyclonedxConfig{MinTransitiveSeverity: &minSeverity})

	testFile, err := os.ReadFile(filepath.Join("examples", file))
	require.NoError(t, err)
	require.NotNil(t, testFile)

	t.Run("default file decomposition", func(t *testing.T) {
		decompose, err := s.Decompose(context.Background(), &sbom_v1.DecomposeOptions{
			Files: []*sbom_v1.SBOMFile{
				{
					FileName: file,
					Data:     testFile,
				},
			},
		})

		require.NotNil(t, decompose)
		require.NoError(t, err)

		require.Equal(t, uint64(100), decompose.TotalNodes)
		require.Len(t, decompose.Vulnerabilities, 5)
		require.Empty(t, decompose.DependencyCycles)
	})

	t.Run("file decomposition with only vulnerable components", func(t *testing.T) {
		decompose, err := s.Decompose(context.Background(), &sbom_v1.DecomposeOptions{
			Files: []*sbom_v1.SBOMFile{
				{
					FileName: file,
					Data:     testFile,
				},
			},
			OnlyVulnerable: true,
		})

		require.NotNil(t, decompose)
		require.NoError(t, err)

		require.Equal(t, uint64(38), decompose.TotalNodes)
		require.Len(t, decompose.Vulnerabilities, 5)
		require.Empty(t, decompose.DependencyCycles)
	})
}
