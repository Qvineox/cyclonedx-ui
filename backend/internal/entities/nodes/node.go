package nodes

import (
	cdx "github.com/CycloneDX/cyclonedx-go"
	sbom_v1 "github.com/Qvineox/cyclonedx-ui/gen/go/api/proto/sbom/v1"
)

type Node struct {
	Component *cdx.Component

	Children []*Node
	Vulns    []cdx.Vulnerability

	// InCycle means node is present in cyclical dependency
	InCycle   bool
	IsVisited bool

	Level int
}

func (n Node) ToProtoV1() *sbom_v1.Component {
	p := sbom_v1.Component{
		Name:            n.Component.Name,
		Group:           n.Component.Group,
		Version:         n.Component.Version,
		Description:     n.Component.Description,
		Type:            string(n.Component.Type),
		BomRef:          n.Component.BOMRef,
		Purl:            &n.Component.PackageURL,
		Children:        make([]*sbom_v1.Component, len(n.Children)),
		Vulnerabilities: make([]*sbom_v1.Vulnerability, len(n.Vulns)),
	}

	for i, child := range n.Children {
		p.Children[i] = child.ToProtoV1()
	}

	// pkg:npm/@rgs-ui-v3/input@1.33.0 <-- pkg:npm/@rgs-ui/hooks-v3@4.0.9 <-- pkg:npm/@rgs-ui-v3/input@1.33.0
	// pkg:npm/@rgs-ui-v3/input@1.33.0 <-- pkg:npm/@rgs-ui/hooks@0.14.11
	// pkg:npm/@rgs-ui-v3/input@1.33.0 <-- pkg:npm/@rgs-ui-v3/tooltip@1.1.6

	// pkg:npm/@rgs-ui-v3/input@1.33.0
	// |
	// |-- pkg:npm/@rgs-ui/hooks-v3@3.6.13

	for i, vuln := range n.Vulns {
		p.Vulnerabilities[i] = &sbom_v1.Vulnerability{
			Id:             vuln.ID,
			Detail:         vuln.Detail,
			Description:    vuln.Description,
			Recommendation: vuln.Recommendation,
			Advisories:     make([]*sbom_v1.Advisory, len(*vuln.Advisories)),
			Affects:        make([]*sbom_v1.Affect, len(*vuln.Affects)),
			Ratings:        make([]*sbom_v1.Rating, len(*vuln.Ratings)),
			Cwes:           make([]int32, len(*vuln.CWEs)),
			//CreatedAt:      timestamppb.New(vuln.Created),
			//PublishedAt:    timestamppb.New(vuln.Published),
			//UpdatedAt:      timestamppb.New(vuln.Updated),
			//RejectedAt:     timestamppb.New(vuln.Rejected),
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

	return &p
}
