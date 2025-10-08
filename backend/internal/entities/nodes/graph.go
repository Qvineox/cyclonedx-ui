package nodes

import (
	"fmt"
	"log/slog"
	"strings"
	"time"

	cdx "github.com/CycloneDX/cyclonedx-go"
	sbom_v1 "github.com/Qvineox/cyclonedx-ui/gen/go/api/proto/sbom/v1"
	"google.golang.org/protobuf/types/known/timestamppb"
)

type DependencyGraph struct {
	Root *Node

	Nodes           map[string]*Node
	Vulnerabilities []cdx.Vulnerability

	TotalNodes       int      `json:"total_nodes"`
	TopologicalOrder []string `json:"topological_order"`

	DetectedCycles [][]string
	CyclePaths     [][]string

	CycleBreakInfo string `json:"cycle_break_info,omitempty"`
}

func (g *DependencyGraph) ToProtoV1() *sbom_v1.Component {
	return g.Root.ToProtoV1()
}

func (g *DependencyGraph) ToProtoDecompositionV1() *sbom_v1.SBOMDecomposition {
	p := sbom_v1.SBOMDecomposition{
		Graph: g.ToProtoV1(),
		// OrderedComponentRefs: g.TopologicalOrder,
		Vulnerabilities:  make([]*sbom_v1.Vulnerability, len(g.Vulnerabilities)),
		TotalNodes:       uint64(g.TotalNodes),
		DependencyCycles: make([]*sbom_v1.DependencyCycle, len(g.DetectedCycles)),
	}

	for i, vuln := range g.Vulnerabilities {
		p.Vulnerabilities[i] = &sbom_v1.Vulnerability{
			Id:             vuln.ID,
			Detail:         vuln.Detail,
			Description:    vuln.Description,
			Recommendation: vuln.Recommendation,
			Advisories:     make([]*sbom_v1.Advisory, len(*vuln.Advisories)),
			Affects:        make([]*sbom_v1.Affect, len(*vuln.Affects)),
			Ratings:        make([]*sbom_v1.Rating, len(*vuln.Ratings)),
			Cwes:           make([]int32, len(*vuln.CWEs)),
		}

		//"2024-11-21T08:27:30+00:00"
		if len(vuln.Created) > 0 {
			at, err := time.Parse(time.RFC3339, vuln.Created)
			if err != nil {
				slog.Warn("failed to parse field",
					slog.String("field", "Created"),
					slog.String("format", "time"),
					slog.String("value", vuln.Created))
			} else {
				p.Vulnerabilities[i].CreatedAt = timestamppb.New(at)
			}
		}

		if len(vuln.Updated) > 0 {
			at, err := time.Parse(time.RFC3339, vuln.Updated)
			if err != nil {
				slog.Warn("failed to parse field",
					slog.String("field", "Updated"),
					slog.String("format", "time"),
					slog.String("value", vuln.Created))
			} else {
				p.Vulnerabilities[i].UpdatedAt = timestamppb.New(at)
			}
		}

		if len(vuln.Published) > 0 {
			at, err := time.Parse(time.RFC3339, vuln.Published)
			if err != nil {
				slog.Warn("failed to parse field",
					slog.String("field", "Published"),
					slog.String("format", "time"),
					slog.String("value", vuln.Created))
			} else {
				p.Vulnerabilities[i].PublishedAt = timestamppb.New(at)
			}
		}

		if len(vuln.Rejected) > 0 {
			at, err := time.Parse(time.RFC3339, vuln.Rejected)
			if err != nil {
				slog.Warn("failed to parse field",
					slog.String("field", "Rejected"),
					slog.String("format", "time"),
					slog.String("value", vuln.Created))
			} else {
				p.Vulnerabilities[i].RejectedAt = timestamppb.New(at)
			}
		}

		if vuln.Source != nil {
			p.Vulnerabilities[i].Source = &sbom_v1.Source{
				Source: vuln.Source.Name,
				Url:    vuln.Source.URL,
			}
		}

		for j, advisory := range *vuln.Advisories {
			p.Vulnerabilities[i].Advisories[j] = &sbom_v1.Advisory{
				Title: advisory.Title,
				Url:   advisory.URL,
			}
		}

		for j, r := range *vuln.Ratings {
			pr := &sbom_v1.Rating{
				Severity:      string(r.Severity),
				Method:        string(r.Method),
				Vector:        r.Vector,
				Justification: r.Justification,
			}

			if r.Score != nil {
				s := float32(*r.Score)
				pr.Score = &s
			}

			if r.Source != nil {
				pr.Source = &sbom_v1.Source{
					Source: r.Source.Name,
					Url:    r.Source.URL,
				}
			}

			p.Vulnerabilities[i].Ratings[j] = pr
		}

		for j, v := range *vuln.CWEs {
			p.Vulnerabilities[i].Cwes[j] = int32(v)
		}

		for j, affect := range *vuln.Affects {
			p.Vulnerabilities[i].Affects[j] = &sbom_v1.Affect{
				Ranges: make([]*sbom_v1.Range, len(*affect.Range)),
			}

			for k, r := range *affect.Range {
				p.Vulnerabilities[i].Affects[j].Ranges[k] = &sbom_v1.Range{
					Version: r.Version,
					Range:   r.Range,
					Status:  string(r.Status),
				}
			}
		}
	}

	for i, cycle := range g.DetectedCycles {
		p.DependencyCycles[i] = &sbom_v1.DependencyCycle{
			Path: cycle,
		}
	}

	return &p
}

func (g *DependencyGraph) RootNodes() []*Node {
	// Считаем, сколько раз каждый узел встречается как зависимость
	dependencyCount := make(map[string]int)
	for _, node := range g.Nodes {
		dependencyCount[node.Component.BOMRef] = 0
	}

	for _, node := range g.Nodes {
		for _, child := range node.Children {
			dependencyCount[child.Component.BOMRef]++
		}
	}

	// Корневые узлы - те, которые никогда не были зависимостями
	var roots []*Node
	for ref, count := range dependencyCount {
		if count == 0 {
			roots = append(roots, g.Nodes[ref])
		}
	}

	return roots
}

func (g *DependencyGraph) TopologicalSort() ([]*cdx.Component, error) {
	visited := make(map[string]bool)
	tempMark := make(map[string]bool)
	var order []*cdx.Component

	var visit func(node *Node) error
	visit = func(node *Node) error {
		if tempMark[node.Component.BOMRef] {
			return fmt.Errorf("found : %s", node.Component.Name)
		}

		if visited[node.Component.BOMRef] {
			return nil
		}

		tempMark[node.Component.BOMRef] = true

		for _, child := range node.Children {
			if err := visit(child); err != nil {
				return err
			}
		}

		tempMark[node.Component.BOMRef] = false
		visited[node.Component.BOMRef] = true

		order = append(order, node.Component)
		return nil
	}

	if err := visit(g.Root); err != nil {
		return nil, err
	}

	for i, j := 0, len(order)-1; i < j; i, j = i+1, j-1 {
		order[i], order[j] = order[j], order[i]
	}

	return order, nil
}

func (g *DependencyGraph) DetectAndResolveCycles() error {
	visited := make(map[string]bool)
	recursionStack := make(map[string]bool)
	var currentPath []string

	var dfs func(node *Node) error
	dfs = func(node *Node) error {
		nodeRef := node.Component.BOMRef

		if !visited[nodeRef] {
			visited[nodeRef] = true
			recursionStack[nodeRef] = true
			currentPath = append(currentPath, nodeRef)

			for _, child := range node.Children {
				childRef := child.Component.BOMRef

				if !visited[childRef] {
					if err := dfs(child); err != nil {
						return err
					}
				} else if recursionStack[childRef] {
					// Обнаружен цикл - сохраняем полный путь
					cycle := g.extractCycle(currentPath, childRef)
					g.DetectedCycles = append(g.DetectedCycles, cycle)
					g.CyclePaths = append(g.CyclePaths, append([]string{}, currentPath...))
				}
			}
		}

		recursionStack[nodeRef] = false
		if len(currentPath) > 0 {
			currentPath = currentPath[:len(currentPath)-1]
		}

		return nil
	}

	for _, node := range g.Nodes {
		if !visited[node.Component.BOMRef] {
			if err := dfs(node); err != nil {
				return err
			}
		}
	}

	// Разрываем циклы
	g.breakCycles()
	return nil
}

func (g *DependencyGraph) extractCycle(path []string, cycleStart string) []string {
	startIndex := -1
	for i, ref := range path {
		if ref == cycleStart {
			startIndex = i
			break
		}
	}

	if startIndex == -1 {
		return path
	}

	cycle := make([]string, len(path)-startIndex)
	copy(cycle, path[startIndex:])
	// Добавляем начальный элемент для замыкания цикла
	cycle = append(cycle, cycleStart)
	return cycle
}

func (g *DependencyGraph) breakCycles() {
	brokenEdges := []string{}

	for _, cycle := range g.DetectedCycles {
		if len(cycle) < 2 {
			continue
		}

		lastNodeRef := cycle[len(cycle)-2]
		firstNodeRef := cycle[0]

		if node, exists := g.Nodes[lastNodeRef]; exists {
			for i, child := range node.Children {
				if child.Component.BOMRef == firstNodeRef {
					brokenEdges = append(brokenEdges,
						fmt.Sprintf("%s -> %s", lastNodeRef, firstNodeRef))

					node.Children = append(node.Children[:i], node.Children[i+1:]...)
					break
				}
			}
		}
	}

	// Помечаем узлы, участвующие в циклах
	for _, cycle := range g.DetectedCycles {
		for _, ref := range cycle {
			if node, exists := g.Nodes[ref]; exists && ref != cycle[len(cycle)-1] {
				node.InCycle = true
			}
		}
	}
}

func (g *DependencyGraph) PrintTree() {
	var printNode func(node *Node, depth int, path map[string]bool)
	printNode = func(node *Node, depth int, path map[string]bool) {
		indent := ""
		for i := 0; i < depth; i++ {
			indent += "  "
		}

		cycleMarker := ""
		if node.InCycle {
			cycleMarker = " [CYCLE]"
		}

		if path[node.Component.BOMRef] {
			cycleMarker = " [CYCLE DETECTED]"
		}

		fmt.Printf("%s└── %s (%s)%s\n", indent, node.Component.Name, node.Component.BOMRef, cycleMarker)

		// Добавляем текущий узел в путь
		newPath := make(map[string]bool)
		for k, v := range path {
			newPath[k] = v
		}
		newPath[node.Component.BOMRef] = true

		for _, child := range node.Children {
			printNode(child, depth+1, newPath)
		}
	}

	printNode(g.Root, 0, make(map[string]bool))
}

func (g *DependencyGraph) BuildCleanGraph(minTransitiveSeverity float64) (*DependencyGraph, error) {
	// Получаем топологический порядок
	topologicalOrder, err := g.TopologicalSort()
	if err != nil {
		return nil, err
	}

	var topologicalRefs []string
	for _, comp := range topologicalOrder {
		topologicalRefs = append(topologicalRefs, comp.BOMRef)
	}

	var buildCleanTree func(node *Node, level int) (*Node, bool)
	buildCleanTree = func(node *Node, level int) (*Node, bool) {
		cleanNode := &Node{
			Component: node.Component,
			Vulns:     node.Vulns,
			Level:     level,
		}

		// check max severity score from all vulns in component
		var maxDirectVulnsScore float64
		for _, v := range node.Vulns {
			for _, r := range *v.Ratings {
				if r.Score != nil && *r.Score > maxDirectVulnsScore {
					maxDirectVulnsScore = *r.Score
				}
			}
		}

		for _, child := range node.Children {
			node_, transVulns_ := buildCleanTree(child, level+1)

			cleanNode.HasTransitiveVulns = transVulns_
			cleanNode.Children = append(cleanNode.Children, node_)
		}

		return cleanNode, maxDirectVulnsScore >= minTransitiveSeverity
	}

	cleanRoot, hasTrans := buildCleanTree(g.Root, 0)
	cleanRoot.HasTransitiveVulns = hasTrans

	totalNodes := countNodes(cleanRoot)

	cycleBreakInfo := ""
	if len(g.DetectedCycles) > 0 {
		cycleBreakInfo = fmt.Sprintf("Автоматически разорвано %d циклов для построения ациклического графа", len(g.DetectedCycles))
	}

	return &DependencyGraph{
		Root:             cleanRoot,
		Nodes:            g.Nodes,
		Vulnerabilities:  g.Vulnerabilities,
		TotalNodes:       totalNodes,
		TopologicalOrder: topologicalRefs,
		DetectedCycles:   g.DetectedCycles,
		CyclePaths:       g.CyclePaths,
		CycleBreakInfo:   cycleBreakInfo,
	}, nil
}

func (g *DependencyGraph) CyclesDetails() string {
	builder := strings.Builder{}

	if len(g.DetectedCycles) == 0 {
		builder.WriteString("dependency cycles not found")
		return builder.String()
	}

	fmt.Printf("found cycles: %d\n", len(g.DetectedCycles))
	for i, cycle := range g.DetectedCycles {
		builder.WriteString(fmt.Sprintf("\ncycle %d:\n", i+1))
		builder.WriteString(fmt.Sprintf("  full path: %s\n", formatCyclePath(cycle)))
		builder.WriteString(fmt.Sprintf("  nodes (%d):\n", len(cycle)-1))
		for j, ref := range cycle[:len(cycle)-1] {
			if node, exists := g.Nodes[ref]; exists {
				builder.WriteString(fmt.Sprintf("    %d. %s (%s)\n", j+1, node.Component.Name, ref))
			}
		}
	}

	return builder.String()
}

func formatCyclePath(cycle []string) string {
	if len(cycle) == 0 {
		return ""
	}

	path := ""
	for i := 0; i < len(cycle)-1; i++ {
		if i > 0 {
			path += " → "
		}
		// Берем короткое имя из BOMRef
		ref := cycle[i]
		if len(ref) > 20 {
			ref = ref[:20] + "..."
		}
		path += ref
	}
	path += " → " + cycle[0] // Замыкаем цикл
	return path
}

func countNodes(root *Node) int {
	count := 1
	for _, child := range root.Children {
		count += countNodes(child)
	}

	return count
}
