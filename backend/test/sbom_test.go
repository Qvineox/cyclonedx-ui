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

const file1 = "sbom.cdx.json"
const file2 = "parent.cdx.json"

//const file1 = "cdxgen_fs_sbom.cdx.json"

func TestBehavior(t *testing.T) {
	s := services.NewSBOMServiceImpl(cfg.CyclonedxConfig{MinTransitiveSeverity: 1.0})

	testFile1, err := os.ReadFile(filepath.Join("examples", file1))
	require.NoError(t, err)
	require.NotNil(t, testFile1)

	testFile2, err := os.ReadFile(filepath.Join("examples", file2))
	require.NoError(t, err)
	require.NotNil(t, testFile2)

	t.Run("default file1 decomposition", func(t *testing.T) {
		decompose, err := s.Decompose(context.Background(), &sbom_v1.DecomposeOptions{
			OnlyVulnerable: false,
			MaxDepth:       12,
			Source: &sbom_v1.DecomposeOptions_Upload{
				Upload: &sbom_v1.SBOMFiles{
					Files: []*sbom_v1.SBOMFile{
						{
							FileName: file1,
							Data:     testFile1,
						},
					},
				},
			},
		})

		require.NotNil(t, decompose)
		require.NoError(t, err)

		require.Equal(t, uint64(100), decompose.TotalNodes)
		require.Len(t, decompose.Vulnerabilities, 5)
		require.Empty(t, decompose.DependencyCycles)
	})

	t.Run("file1 decomposition with only vulnerable components", func(t *testing.T) {
		decompose, err := s.Decompose(context.Background(), &sbom_v1.DecomposeOptions{
			OnlyVulnerable: true,
			MaxDepth:       12,
			Source: &sbom_v1.DecomposeOptions_Upload{
				Upload: &sbom_v1.SBOMFiles{
					Files: []*sbom_v1.SBOMFile{
						{
							FileName: file1,
							Data:     testFile1,
						},
					},
				},
			},
		})

		require.NotNil(t, decompose)
		require.NoError(t, err)

		require.Equal(t, uint64(38), decompose.TotalNodes)
		require.Len(t, decompose.Vulnerabilities, 5)
		require.Empty(t, decompose.DependencyCycles)
	})

	t.Run("file1 decomposition metadata", func(t *testing.T) {
		decompose, err := s.Decompose(context.Background(), &sbom_v1.DecomposeOptions{
			Source: &sbom_v1.DecomposeOptions_Upload{
				Upload: &sbom_v1.SBOMFiles{
					Files: []*sbom_v1.SBOMFile{
						{
							FileName: file1,
							Data:     testFile1,
						},
					},
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

	t.Run("missing sbom files comparison", func(t *testing.T) {
		compare, err := s.Compare(context.Background(), &sbom_v1.CompareOptions{
			MaxDepth: 12,
			Upload: &sbom_v1.SBOMFiles{
				Files: []*sbom_v1.SBOMFile{
					{
						FileName: file1,
						Data:     testFile1,
					},
				},
			},
		})

		require.Nil(t, compare)
		require.Error(t, err)
	})

	t.Run("sbom files comparison", func(t *testing.T) {
		compare, err := s.Compare(context.Background(), &sbom_v1.CompareOptions{
			MaxDepth: 12,
			Upload: &sbom_v1.SBOMFiles{
				Files: []*sbom_v1.SBOMFile{
					{
						FileName: file1,
						Data:     testFile1,
					},
					{
						FileName: file2,
						Data:     testFile2,
					},
				},
			},
		})

		require.NotNil(t, compare)
		require.NoError(t, err)
	})
}
