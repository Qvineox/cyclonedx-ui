export interface IDecomposeOptions {
    fileUuid?: string;

    upload: UploadOptions

    maxDepth: number;
    onlyVulnerable: boolean;
}

export interface UploadOptions {
    files?: Array<ISBOMFile>

    projectUid?: string;
}

export interface ISBOMFile {
    fileName: string;
    version?: string | undefined;
    data: string;
}

export interface ISBOMDecomposition {
    id: number | undefined;
    serialNumber: string | undefined;
    md5: string | undefined;

    metaData: IMeta | undefined;

    graph: IComponent

    components?: Array<IComponent>
    vulnerabilities?: Array<IVulnerability>

    totalNodes: string
    dependencyCycles?: Array<IDependencyCycle>
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
    source: ISource | undefined;
    score: number | undefined;

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

export interface IMeta {
    bomVersion: string;

    tools: Array<IComponent>;
    project: IComponent;

    authors: IContact[];
    lifecycles: ILifecycle[];

    properties: { [key: string]: string };

    createdAt: Date | undefined;
}

export interface IMeta_PropertiesEntry {
    key: string;
    value: string;
}

export interface ILifecycle {
    phase: string;
    name: string;
    description: string;
}

export interface IContact {
    email: string;
    name: string;
    phone: string;
    bomRef: string;
}