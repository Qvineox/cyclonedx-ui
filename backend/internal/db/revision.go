package db

import (
	"context"
	"time"

	v1 "github.com/Qvineox/cyclonedx-ui/gen/go/api/proto/project/v1"
	"google.golang.org/protobuf/types/known/timestamppb"
	"gorm.io/datatypes"
	"gorm.io/gorm"
)

type Revision struct {
	ID *uint64 `gorm:"column:id;primaryKey;autoIncrement:true"`

	Name *string                     `gorm:"column:name"`
	Tags datatypes.JSONSlice[string] `gorm:"column:tags;type:jsonb"`

	ProjectID   *uint64 `gorm:"column:project_id"`
	ProjectSlug *string `gorm:"column:project_slug"`

	VCSUrl        *string                     `gorm:"column:vcs_url"`
	GitTags       datatypes.JSONSlice[string] `gorm:"column:git_tags"`
	GitBranches   datatypes.JSONSlice[string] `gorm:"column:git_branches"`
	GitCommitHash *string                     `gorm:"column:git_commit_hash"`

	CreatedBy *string `gorm:"column:created_by"`

	SBOMFileUUID datatypes.UUID `gorm:"column:sbom_file_uuid"`
	SBOMFile     SbomFile       `gorm:"foreignKey:sbom_file_uuid;constraint:OnUpdate:CASCADE,OnDelete:SET NULL;"`

	CreatedAt *time.Time `gorm:"column:created_at;autoCreateTime"`
	UpdatedAt *time.Time `gorm:"column:updated_at;autoUpdateTime"`

	DeletedAt gorm.DeletedAt `gorm:"index"`
}

func (r Revision) toProtoV1() *v1.Revision {
	r_ := v1.Revision{
		Id:            *r.ID,
		Name:          r.Name,
		Tags:          r.Tags,
		ProjectId:     *r.ProjectID,
		ProjectSlug:   *r.ProjectSlug,
		GitTags:       r.GitTags,
		GitBranches:   r.GitBranches,
		GitCommitHash: r.GitCommitHash,
		VcsUrl:        r.VCSUrl,
		CreatedBy:     r.CreatedBy,
		CreatedAt:     timestamppb.New(*r.CreatedAt),
		UpdatedAt:     timestamppb.New(*r.UpdatedAt),
	}

	if !r.SBOMFileUUID.IsNil() {
		uuid_ := r.SBOMFileUUID.String()
		r_.SbomFileUuid = &uuid_
	}

	return &r_
}

type RevisionRepoImpl struct {
	*gorm.DB
}

func (repo RevisionRepoImpl) GetProjectRevisionByID(ctx context.Context, projectID uint64, revisionID uint64) (*v1.Revision, error) {
	//TODO implement me
	panic("implement me")
}

func (repo RevisionRepoImpl) GetProjectRevisionBySlug(ctx context.Context, projectSlug string, revisionID uint64) (*v1.Revision, error) {
	//TODO implement me
	panic("implement me")
}

func (repo RevisionRepoImpl) UpdateProjectRevision(ctx context.Context, revision *v1.Revision) (*v1.Revision, error) {
	//TODO implement me
	panic("implement me")
}

func NewRevisionRepoImpl(DB *gorm.DB) *RevisionRepoImpl {
	return &RevisionRepoImpl{DB: DB}
}
