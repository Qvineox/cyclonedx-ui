package services

import (
	"context"
	"errors"
	"log/slog"

	"github.com/Qvineox/cyclonedx-ui/gen/go/api/proto/project/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"gorm.io/gorm"
)

type ProjectServiceImpl struct {
	projectRepo  IProjectRepo
	revisionRepo IRevisionRepo
}

func NewProjectServiceImpl(projectRepo IProjectRepo, revisionRepo IRevisionRepo) *ProjectServiceImpl {
	return &ProjectServiceImpl{projectRepo: projectRepo, revisionRepo: revisionRepo}
}

type IProjectRepo interface {
	GetProjectByID(ctx context.Context, id uint64) (*project_v1.Project, error)
	GetProjectBySlug(ctx context.Context, slug string) (*project_v1.Project, error)

	GetProjectsByQueryFilter(ctx context.Context, filter *project_v1.ProjectsQueryFilter) ([]*project_v1.Project, error)

	CreateProject(ctx context.Context, project *project_v1.Project) (*project_v1.Project, error)
	UpdateProject(ctx context.Context, project *project_v1.Project) (*project_v1.Project, error)
}

type IRevisionRepo interface {
	GetProjectRevisionByID(ctx context.Context, projectID uint64, revisionID uint64) (*project_v1.Revision, error)
	GetProjectRevisionBySlug(ctx context.Context, projectSlug string, revisionID uint64) (*project_v1.Revision, error)

	UpdateProjectRevision(ctx context.Context, revision *project_v1.Revision) (*project_v1.Revision, error)
}

func (service ProjectServiceImpl) GetProjectsByQueryFilter(ctx context.Context, filter *project_v1.ProjectsQueryFilter) (*project_v1.ProjectsList, error) {
	projects, err := service.projectRepo.GetProjectsByQueryFilter(ctx, filter)
	if err != nil {
		return nil, status.Error(codes.Internal, "failed to find projects by filter: "+err.Error())
	}

	return &project_v1.ProjectsList{List: projects}, nil
}

func (service ProjectServiceImpl) GetProject(ctx context.Context, filter *project_v1.ProjectsQueryFilter) (*project_v1.Project, error) {
	var project *project_v1.Project
	var err error

	switch v := filter.GetUid().(type) {
	case *project_v1.ProjectsQueryFilter_Id:
		project, err = service.projectRepo.GetProjectByID(ctx, v.Id)
	case *project_v1.ProjectsQueryFilter_Slug:
		project, err = service.projectRepo.GetProjectBySlug(ctx, v.Slug)
	default:
		return nil, status.Error(codes.InvalidArgument, "project uid is required")
	}

	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, status.Error(codes.NotFound, "project not found")
	} else if err != nil {
		slog.Error("failed to query project", slog.String("error", err.Error()))
		return nil, status.Error(codes.Internal, "failed to find project by id: "+err.Error())
	}

	return project, nil
}

func (service ProjectServiceImpl) GetProjectRevision(ctx context.Context, query *project_v1.ProjectRevisionQuery) (*project_v1.Revision, error) {
	var revision *project_v1.Revision
	var err error

	switch v := query.GetProjectUid().(type) {
	case *project_v1.ProjectRevisionQuery_ProjectId:
		revision, err = service.revisionRepo.GetProjectRevisionByID(ctx, v.ProjectId, query.GetRevisionId())
	case *project_v1.ProjectRevisionQuery_ProjectSlug:
		revision, err = service.revisionRepo.GetProjectRevisionBySlug(ctx, v.ProjectSlug, query.GetRevisionId())
	default:
		return nil, status.Error(codes.InvalidArgument, "revision uid is required")
	}

	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, status.Error(codes.NotFound, "project not found")
	} else if err != nil {
		slog.Error("failed to query project", slog.String("error", err.Error()))
		return nil, status.Error(codes.Internal, "failed to find project by id: "+err.Error())
	}

	return revision, nil
}

func (service ProjectServiceImpl) CreateProject(ctx context.Context, project *project_v1.Project) (*project_v1.Project, error) {
	project_, err := service.projectRepo.CreateProject(ctx, project)
	if err != nil {
		slog.Error("failed to create project", slog.String("error", err.Error()))
		return nil, status.Error(codes.Internal, "failed to create project: "+err.Error())
	}

	return project_, nil
}

func (service ProjectServiceImpl) UpdateProject(ctx context.Context, project *project_v1.Project) (*project_v1.Project, error) {
	project_, err := service.projectRepo.UpdateProject(ctx, project)
	if err != nil {
		slog.Error("failed to update project", slog.String("error", err.Error()))
		return nil, status.Error(codes.Internal, "failed to update project: "+err.Error())
	}

	return project_, nil
}

func (service ProjectServiceImpl) UpdateProjectRevision(ctx context.Context, revision *project_v1.Revision) (*project_v1.Revision, error) {
	revision_, err := service.revisionRepo.UpdateProjectRevision(ctx, revision)
	if err != nil {
		slog.Error("failed to update revision", slog.String("error", err.Error()))
		return nil, status.Error(codes.Internal, "failed to update revision: "+err.Error())
	}

	return revision_, nil
}
