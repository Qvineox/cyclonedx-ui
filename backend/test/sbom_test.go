package test

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/Qvineox/cyclonedx-ui/cfg"
	sbom_v1 "github.com/Qvineox/cyclonedx-ui/gen/go/api/proto/sbom/v1"
	"github.com/Qvineox/cyclonedx-ui/internal/services"
	"github.com/stretchr/testify/require"
)

const file = "sbom.cdx.json"

//const file = "cdxgen_fs_sbom.cdx.json"

func TestBehavior(t *testing.T) {
	s := services.NewSBOMServiceImpl(cfg.CyclonedxConfig{MinTransitiveSeverity: 1.0})

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
			OnlyVulnerable: false,
			MaxDepth:       12,
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
			MaxDepth:       12,
		})

		require.NotNil(t, decompose)
		require.NoError(t, err)

		require.Equal(t, uint64(38), decompose.TotalNodes)
		require.Len(t, decompose.Vulnerabilities, 5)
		require.Empty(t, decompose.DependencyCycles)
	})

	t.Run("file decomposition metadata", func(t *testing.T) {
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

		require.NotNil(t, decompose.MetaData)
		require.EqualValues(t, cdx.SpecVersion1_6, decompose.MetaData.BomVersion)

		require.Len(t, decompose.MetaData.Tools, 1)

		require.EqualValues(t, "urn:uuid:c5bb0cec-cb65-40a3-bb66-c89a37675180", *decompose.SerialNumber)
		require.EqualValues(t, "d07be9f39341527b9c94cf24c1b8601c", *decompose.Md5)
		require.Zero(t, decompose.Id)

		require.Equal(t, "trivy", decompose.MetaData.Tools[0].Name)
		require.Equal(t, "0.67.0", decompose.MetaData.Tools[0].Version)

		require.Equal(t, "S:/Projects/cyclonedx-ui/backend", decompose.MetaData.Project.Name)
		require.Equal(t, "application", decompose.MetaData.Project.Type)

		require.Empty(t, decompose.MetaData.Lifecycles)
		require.Empty(t, decompose.MetaData.Properties)
		require.Empty(t, decompose.MetaData.Authors)
	})
}
