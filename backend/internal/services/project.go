package services

import (
	"context"
	"github.com/Qvineox/cyclonedx-ui/cfg"
	"github.com/Qvineox/cyclonedx-ui/gen/go/api/proto/project/v1"
)

type ProjectServiceImpl struct {
	repo cfg.DatabaseConfig
}

func (service ProjectServiceImpl) GetProjectsByQueryFilter(ctx context.Context, filter *project_v1.ProjectsQueryFilter) (*project_v1.ProjectsList, error) {
	//TODO implement me
	panic("implement me")
}

func (service ProjectServiceImpl) GetProject(ctx context.Context, filter *project_v1.ProjectsQueryFilter) (*project_v1.Project, error) {
	//TODO implement me
	panic("implement me")
}

func (service ProjectServiceImpl) GetProjectRevision(ctx context.Context, query *project_v1.ProjectRevisionQuery) (*project_v1.Revision, error) {
	//TODO implement me
	panic("implement me")
}

func (service ProjectServiceImpl) CreateProject(ctx context.Context, project *project_v1.Project) (*project_v1.Project, error) {
	//TODO implement me
	panic("implement me")
}

func (service ProjectServiceImpl) UpdateProject(ctx context.Context, project *project_v1.Project) (*project_v1.Project, error) {
	//TODO implement me
	panic("implement me")
}

func (service ProjectServiceImpl) UpdateProjectRevision(ctx context.Context, revision *project_v1.Revision) (*project_v1.Project, error) {
	//TODO implement me
	panic("implement me")
}
