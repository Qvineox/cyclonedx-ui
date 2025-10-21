package db

import "gorm.io/gorm"

type RevisionRepoImpl struct {
	*gorm.DB
}

func NewRevisionRepoImpl(DB *gorm.DB) *RevisionRepoImpl {
	return &RevisionRepoImpl{DB: DB}
}
