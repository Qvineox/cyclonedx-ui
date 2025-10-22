package test

import (
	"fmt"
	"testing"

	"github.com/Qvineox/cyclonedx-ui/cfg"
	"github.com/Qvineox/cyclonedx-ui/internal/db"
	"github.com/stretchr/testify/require"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
)

//const file = "cdxgen_fs_sbom.cdx.json"

func TestDatabase(t *testing.T) {
	config := cfg.NewAppConfigFromEnv()
	require.NotNil(t, config.Database)

	dsn := fmt.Sprintf("host=%s port=%d user=%s password=%s database=%s sslmode=disable TimeZone=%s",
		config.Database.Host,
		config.Database.Port,
		config.Database.User,
		config.Database.Pass,
		config.Database.Database,
		config.Database.Timezone,
	)

	orm, err := gorm.Open(postgres.Open(dsn), &gorm.Config{})
	require.NoError(t, err)

	t.Run("migrations", func(t *testing.T) {
		err = orm.AutoMigrate(
			db.Project{},
			db.Revision{},
			db.SbomFile{},
		)

		require.NoError(t, err)
	})
}
