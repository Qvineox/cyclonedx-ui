package services

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"path/filepath"
	"time"

	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/Qvineox/cyclonedx-ui/cfg"
	sbom_v1 "github.com/Qvineox/cyclonedx-ui/gen/go/api/proto/sbom/v1"
	"github.com/Qvineox/cyclonedx-ui/internal/entities/nodes"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type SBOMServiceImpl struct {
	config cfg.CyclonedxConfig
}

func NewSBOMServiceImpl(config cfg.CyclonedxConfig) *SBOMServiceImpl {
	return &SBOMServiceImpl{config: config}
}

func (service SBOMServiceImpl) Decompose(ctx context.Context, options *sbom_v1.DecomposeOptions) (*sbom_v1.SBOMDecomposition, error) {
	if options.GetUuid() != "" {
		return nil, status.Error(codes.Unimplemented, "uuid query not supported")
	}

	upload := options.GetUpload()
	if upload == nil || upload.Files == nil || len(upload.Files) == 0 {
		return nil, status.Error(codes.InvalidArgument, "files not provided")
	} else if len(upload.Files) > 1 {
		return nil, status.Error(codes.Unimplemented, "multiple files provided")
	}

	var format cdx.BOMFileFormat
	var startedAt = time.Now()

	switch filepath.Ext(upload.Files[0].FileName) {
	case ".json":
		format = cdx.BOMFileFormatJSON
	default:
		slog.Error("unsupported sbom file format format", slog.String("format", filepath.Ext(upload.Files[0].GetFileName())))
		return nil, status.Error(codes.Unimplemented, "file format not supported")
	}

	slog.Info("starting sbom decomposition",
		slog.Bool("only_vulnerable", options.GetOnlyVulnerable()),
		slog.Uint64("max_depth", options.GetMaxDepth()),
	)

	var sbom cdx.BOM
	decoder := cdx.NewBOMDecoder(bytes.NewReader(upload.Files[0].Data), format)
	err := decoder.Decode(&sbom)
	if err != nil {
		slog.Error("failed to decode sbom", slog.String("file_name", upload.Files[0].GetFileName()), slog.String("error", err.Error()))
		return nil, status.Error(codes.Internal, "failed to decode sbom file: "+err.Error())
	}

	//	Parse the SBOM.
	//	Create a map for nodes by bom-ref.
	//	For each component, create a node.
	//	For each dependency in the dependencies section, find a node by ref, and then for each dependsOn , find a node and add it to the Deps of that node.
	//	Now we have a nodes, but could it be disconnected? Yes, but in the SBOM, all dependencies are usually connected to the root.
	//	We can find root nodes: those that don't appear as dependencies in the dependencies section (i.e., there are no nodes that depend on them) OR those that are specified as root in the metadata.

	graph, err := BuildDependencyGraph(&sbom)
	if err != nil {
		slog.Error("failed to build dependency graph", slog.String("file_name", upload.Files[0].GetFileName()), slog.String("error", err.Error()))
		return nil, status.Error(codes.Internal, "failed to build dependency graph: "+err.Error())
	}

	if len(graph.CyclePaths) > 0 {
		slog.Info("cycles detected in dependency graph",
			slog.String("file_name", upload.Files[0].GetFileName()),
			slog.Uint64("cycle_count", uint64(len(graph.CyclePaths))),
		)
	}

	cleanGraph, err := graph.BuildCleanGraph(service.config.MinTransitiveSeverity, options.GetOnlyVulnerable(), int(options.GetMaxDepth()))
	if err != nil {
		slog.Error("failed to build dependency graph",
			slog.String("file_name", upload.Files[0].GetFileName()),
			slog.String("error", err.Error()),
		)

		return nil, status.Error(codes.Internal, "failed to build dependency graph: "+err.Error())
	}

	slog.Info("sbom decomposition finished successfully",
		slog.String("file_name", upload.Files[0].GetFileName()),
		slog.Int("total_nodes_count", cleanGraph.TotalNodes),
		slog.Int("total_cycles_resolved", len(cleanGraph.DetectedCycles)),
		slog.Duration("time_taken_seconds", time.Since(startedAt).Round(time.Second)),
	)

	return cleanGraph.ToProtoDecompositionV1(), nil
}

func BuildDependencyGraph(sbom *cdx.BOM) (*nodes.DependencyGraph, error) {
	graph := &nodes.DependencyGraph{
		Nodes:          make(map[string]*nodes.Node),
		DetectedCycles: [][]string{},
		CyclePaths:     [][]string{},
	}

	// save all vulnerabilities into map
	var componentVulns = make(map[string][]cdx.Vulnerability)
	if sbom.Vulnerabilities != nil {
		graph.Vulnerabilities = *sbom.Vulnerabilities

		for _, vuln := range *sbom.Vulnerabilities {
			for _, affected := range *vuln.Affects {
				v, ok := componentVulns[affected.Ref]
				if !ok {
					componentVulns[affected.Ref] = make([]cdx.Vulnerability, 0)
					componentVulns[affected.Ref] = append(componentVulns[affected.Ref], vuln)
				} else {
					componentVulns[affected.Ref] = append(v, vuln)
				}
			}
		}
	}

	for _, comp := range *sbom.Components {
		vulns := componentVulns[comp.BOMRef]

		graph.Nodes[comp.BOMRef] = &nodes.Node{
			Component: &comp,
			Vulns:     vulns,
			Children:  []*nodes.Node{},
		}
	}

	for _, dep := range *sbom.Dependencies {
		parentNode, exists := graph.Nodes[dep.Ref]
		if !exists {
			continue
		}

		for _, childRef := range *dep.Dependencies {
			childNode, exists := graph.Nodes[childRef]
			if exists {
				parentNode.Children = append(parentNode.Children, childNode)
			}
		}
	}

	// Обнаруживаем и обрабатываем циклы
	if err := graph.DetectAndResolveCycles(); err != nil {
		return nil, err
	}

	// find root nodes with no dependencies (can be root modules or standalone dependencies)
	rootNodes := graph.RootNodes()
	if len(rootNodes) == 0 {
		return nil, errors.New("dependency graph is missing root node")
	}

	// find or create root component
	if sbom.Metadata != nil && sbom.Metadata.Component != nil {
		graph.Root = &nodes.Node{
			Component: sbom.Metadata.Component,
			Children:  rootNodes,
		}
	} else {
		return nil, errors.New("dependency graph is missing or has no root component")
	}

	// // create virtual root if not found
	//if len(rootNodes) > 1 {
	//	nodes.createVirtualRoot(rootNodes)
	//} else {
	//	nodes.Root = rootNodes[0]
	//}

	return graph, nil
}
