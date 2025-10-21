package db

import "gorm.io/gorm"

type ProjectRepoImpl struct {
	*gorm.DB
}

func NewProjectRepoImpl(DB *gorm.DB) *ProjectRepoImpl {
	return &ProjectRepoImpl{DB: DB}
}
