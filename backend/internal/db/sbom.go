package db

import (
	"context"
	"gorm.io/gorm"
	"time"

	"github.com/CycloneDX/cyclonedx-go"
	"gorm.io/datatypes"
)

type SbomFile struct {
	UUID datatypes.UUID `gorm:"primaryKey;column:uuid"`

	Data datatypes.JSONType[cyclonedx.BOM] `gorm:"column:data"`

	CreatedAt *time.Time `gorm:"column:created_at;autoCreateTime"`
	UpdatedAt *time.Time `gorm:"column:updated_at;autoUpdateTime"`
}

type ISBOMFileRepo interface {
	CreateSBOMFile(ctx context.Context, file *SbomFile) error
}

type SBOMFileRepoImpl struct {
	*gorm.DB
}

func (repo SBOMFileRepoImpl) CreateSBOMFile(ctx context.Context, file *SbomFile) error {
	return repo.Save(&file).Error
}
