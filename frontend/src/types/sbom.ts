export interface ISBOMDecomposition {
    graph: IComponent
    vulnerabilities: Array<IVulnerability>
    totalNodes: string
    dependencyCycles: Array<string>
}

export interface IComponent {
    name: string

    group: string
    version: string
    description: string

    type: string
    level: number

    bomRef: string
    purl: string

    children: Array<IComponent>
    vulnerabilities: Array<IVulnerability>

    hasTransitiveVulns: boolean
}

export interface IVulnerability {
    id: string
    source: ISource

    description: string
    detail: string
    recommendation: string

    ratings: Rating[]
    cwes: number[]

    advisories: IAdvisory[]
    affects: IAffect[]

    publishedAt: string
    updatedAt: string
}

export interface Rating {
    source: ISource
    score?: number

    severity: string

    method: string
    vector: string
    justification: string
}

export interface ISource {
    source: string
    url: string
}

export interface IAdvisory {
    title: string
    url: string
}

export interface IAffect {
    ranges: Range[]
}

export interface Range {
    version: string
    range: string
    status: string
}