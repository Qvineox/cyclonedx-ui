export interface ISBOMDecomposition {
    graph: IComponent

    components: Array<IComponent>
    vulnerabilities: Array<IVulnerability>

    totalNodes: string
    dependencyCycles: Array<IDependencyCycle>
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
    maxSeverity: number
    totalCveCount: number
}

export interface IVulnerability {
    id: string
    source: ISource

    description: string
    detail: string
    recommendation: string

    maxRating: number
    ratings: IRating[]
    cwes: number[]

    advisories: IAdvisory[]
    affects: IAffect[]

    publishedAt: string
    updatedAt: string
}

export interface IRating {
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
    ref: string
    ranges: Range[]
}

export interface Range {
    version: string
    range: string
    status: string
}

export interface IDependencyCycle {
    path: Array<string>
}