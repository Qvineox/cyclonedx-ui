package nodes

import (
	"fmt"
	"log/slog"

	cdx "github.com/CycloneDX/cyclonedx-go"
	sbom_v1 "github.com/Qvineox/cyclonedx-ui/gen/go/api/proto/sbom/v1"
)

type DependencyGraph struct {
	Root *Node

	Nodes map[string]*Node
	Vulns []cdx.Vulnerability

	Cycles [][]string

	TotalNodes       int
	TopologicalOrder []string
}

func (g *DependencyGraph) ToProtoV1() *sbom_v1.Component {
	return g.Root.ToProtoV1()
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
					cycle := g.extractCycle(currentPath, childRef)
					g.Cycles = append(g.Cycles, cycle)
					g.markCycle(cycle)
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

func (g *DependencyGraph) TopologicalSortWithCycleBreaking() ([]*cdx.Component, error) {
	if len(g.Cycles) > 0 {
		slog.Warn(fmt.Sprintf("dependency cycle found, trying to break: %v\n", g.Cycles))
		g.breakCycles()
	}

	return g.TopologicalSort()
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
	return cycle
}

func (g *DependencyGraph) markCycle(cycle []string) {
	for _, ref := range cycle {
		if node, exists := g.Nodes[ref]; exists {
			node.InCycle = true
		}
	}
}

func (g *DependencyGraph) breakCycles() {
	for _, cycle := range g.Cycles {
		if len(cycle) < 2 {
			continue
		}

		lastNodeRef := cycle[len(cycle)-1]
		firstNodeRef := cycle[0]

		if node, exists := g.Nodes[lastNodeRef]; exists {
			for i, child := range node.Children {
				if child.Component.BOMRef == firstNodeRef {
					node.Children = append(node.Children[:i], node.Children[i+1:]...)
					break
				}
			}
		}
	}

	g.Cycles = [][]string{}
	for _, node := range g.Nodes {
		node.InCycle = false
	}
}

func (g *DependencyGraph) BuildCleanGraph() (*DependencyGraph, error) {
	topologicalOrder, err := g.TopologicalSort()
	if err != nil {
		return nil, err
	}

	var topologicalRefs []string
	for _, comp := range topologicalOrder {
		topologicalRefs = append(topologicalRefs, comp.BOMRef)
	}

	var buildCleanTree func(node *Node, level int) *Node
	buildCleanTree = func(node *Node, level int) *Node {
		cleanNode := Node{
			Component: node.Component,
			Children:  node.Children,
			Vulns:     node.Vulns,
			Level:     level,
		}

		for _, child := range node.Children {
			cleanNode.Children = append(cleanNode.Children, buildCleanTree(child, level+1))
		}

		return &cleanNode
	}

	cleanRoot := buildCleanTree(g.Root, 0)
	totalNodes := countNodes(cleanRoot)

	return &DependencyGraph{
		Root:             cleanRoot,
		TotalNodes:       totalNodes,
		TopologicalOrder: topologicalRefs,
	}, nil
}

func countNodes(root *Node) int {
	count := 1
	for _, child := range root.Children {
		count += countNodes(child)
	}

	return count
}
