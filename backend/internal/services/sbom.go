package services

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"path/filepath"

	cdx "github.com/CycloneDX/cyclonedx-go"
	sbom_v1 "github.com/Qvineox/cyclonedx-ui/gen/go/api/proto/sbom/v1"
	"github.com/Qvineox/cyclonedx-ui/internal/entities/nodes"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type SBOMServiceImpl struct {
}

func NewSBOMServiceImpl() *SBOMServiceImpl {
	return &SBOMServiceImpl{}
}

func (service SBOMServiceImpl) Decompose(ctx context.Context, file *sbom_v1.SBOMFile) (*sbom_v1.SBOMDecomposition, error) {
	if file.FileName == "" || len(file.Data) == 0 {
		return nil, status.Error(codes.InvalidArgument, "file name is missing or file is empty")
	}

	var format cdx.BOMFileFormat

	switch filepath.Ext(file.FileName) {
	case ".json":
		format = cdx.BOMFileFormatJSON
	default:
		return nil, status.Error(codes.Unimplemented, "file format not supported")

	}

	var sbom cdx.BOM
	decoder := cdx.NewBOMDecoder(bytes.NewReader(file.Data), format)
	err := decoder.Decode(&sbom)
	if err != nil {
		return nil, status.Error(codes.Internal, "failed to decode SBOM: "+err.Error())
	}

	//	Parse the SBOM.
	//	Create a map for nodes by bom-ref.
	//	For each component, create a node.
	//	For each dependency in the dependencies section, find a node by ref, and then for each dependsOn , find a node and add it to the Deps of that node.
	//	Now we have a nodes, but could it be disconnected? Yes, but in the SBOM, all dependencies are usually connected to the root.
	//	We can find root nodes: those that don't appear as dependencies in the dependencies section (i.e., there are no nodes that depend on them) OR those that are specified as root in the metadata.

	graph, err := BuildDependencyGraph(&sbom)
	if err != nil {
		panic(err)
	}

	cleanGraph, err := graph.BuildCleanGraph()
	if err != nil {
		panic(err)
	}

	// Пытаемся выполнить топологическую сортировку
	ordered, err := graph.TopologicalSort()
	if err != nil {
		fmt.Printf("Ошибка при сортировке: %v\n", err)
		fmt.Println("Пытаемся разорвать циклы и повторить...")

		// Используем версию с разрывом циклов
		ordered, err = graph.TopologicalSortWithCycleBreaking()
		if err != nil {
			panic(err)
		}
	}

	fmt.Println("\nТопологический порядок после обработки циклов:")
	for i, comp := range ordered {
		fmt.Printf("%d. %s (%s)\n", i+1, comp.Name, comp.BOMRef)
	}

	return &sbom_v1.SBOMDecomposition{Graph: cleanGraph.ToProtoV1()}, nil
}

func BuildDependencyGraph(sbom *cdx.BOM) (*nodes.DependencyGraph, error) {
	graph := &nodes.DependencyGraph{
		Nodes: make(map[string]*nodes.Node),
		Vulns: *sbom.Vulnerabilities,
	}

	// save all vulnerabilities into map
	var componentVulns = make(map[string][]cdx.Vulnerability)
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

	// create nodes for all dependencies
	for _, comp := range *sbom.Components {
		graph.Nodes[comp.BOMRef] = &nodes.Node{
			Component: &comp,
			Children:  []*nodes.Node{},
			Vulns:     componentVulns[comp.BOMRef],
			InCycle:   false,
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

	//
	//// Если несколько корней, создаем виртуальный корень
	//if len(rootNodes) > 1 {
	//	nodes.createVirtualRoot(rootNodes)
	//} else {
	//	nodes.Root = rootNodes[0]
	//}

	return graph, nil
}
