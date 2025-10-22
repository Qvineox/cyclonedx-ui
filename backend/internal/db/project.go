package db

import (
	"context"
	"errors"
	"time"

	v1 "github.com/Qvineox/cyclonedx-ui/gen/go/api/proto/project/v1"
	"google.golang.org/protobuf/types/known/timestamppb"
	"gorm.io/datatypes"
	"gorm.io/gorm"
)

type Project struct {
	ID   *uint64 `gorm:"column:id;primaryKey;autoIncrement:true"`
	Slug string  `gorm:"column:slug;unique;not null"`

	Name        string                      `gorm:"column:name;index;not null"`
	Description *string                     `gorm:"column:description"`
	Tags        datatypes.JSONSlice[string] `gorm:"column:tags;type:jsonb"`

	VCSUrl *string `gorm:"column:vcs_url"`

	CreatedAt *time.Time `gorm:"column:created_at;autoCreateTime"`
	UpdatedAt *time.Time `gorm:"column:updated_at;autoUpdateTime"`

	Revisions []Revision `gorm:"foreignKey:project_id;references:id;constraint:OnUpdate:CASCADE,OnDelete:SET NULL;"`

	DeletedAt gorm.DeletedAt `gorm:"index"`
}

func (p Project) toProtoV1() *v1.Project {
	p_ := v1.Project{
		Id:          *p.ID,
		Name:        p.Name,
		Slug:        p.Slug,
		Description: p.Description,
		Tags:        p.Tags,
		VcsUrl:      p.VCSUrl,
		Revisions:   make([]*v1.Revision, len(p.Revisions)),
		CreatedAt:   timestamppb.New(*p.CreatedAt),
		UpdatedAt:   timestamppb.New(*p.UpdatedAt),
	}

	for i, r := range p.Revisions {
		p_.Revisions[i] = r.toProtoV1()
	}

	return &p_
}

type ProjectRepoImpl struct {
	*gorm.DB
}

func NewProjectRepoImpl(DB *gorm.DB) *ProjectRepoImpl {
	return &ProjectRepoImpl{DB: DB}
}

func (repo ProjectRepoImpl) GetProjectByID(ctx context.Context, id uint64) (*v1.Project, error) {
	var p Project

	err := repo.Find(&p, id).Error
	if err != nil {
		return nil, err
	}

	return p.toProtoV1(), nil
}

func (repo ProjectRepoImpl) GetProjectBySlug(ctx context.Context, slug string) (*v1.Project, error) {
	var p Project

	err := repo.Where(&p, "slug = ?", slug).Error
	if err != nil {
		return nil, err
	}

	return p.toProtoV1(), nil
}

func (repo ProjectRepoImpl) GetProjectsByQueryFilter(ctx context.Context, filter *v1.ProjectsQueryFilter) ([]*v1.Project, error) {
	return nil, errors.New("not implemented")
}

func (repo ProjectRepoImpl) CreateProject(ctx context.Context, project_ *v1.Project) (*v1.Project, error) {
	var p = Project{
		Slug:        project_.GetSlug(),
		Name:        project_.GetName(),
		Description: project_.Description,
		Tags:        project_.Tags,
		VCSUrl:      project_.VcsUrl,
	}

	err := repo.Create(&p).Error
	if err != nil {
		return nil, err
	}

	return p.toProtoV1(), nil
}

func (repo ProjectRepoImpl) UpdateProject(ctx context.Context, project_ *v1.Project) (*v1.Project, error) {
	var p = Project{
		ID:          &project_.Id,
		Slug:        project_.Slug,
		Name:        project_.Name,
		Description: project_.Description,
		Tags:        project_.Tags,
		VCSUrl:      project_.VcsUrl,
	}

	err := repo.Save(&p).Error
	if err != nil {
		return nil, err
	}

	return p.toProtoV1(), nil
}
