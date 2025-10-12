import Form from 'react-bootstrap/Form';
import Button from 'react-bootstrap/Button';
import {Fragment, useEffect, useState} from "react";
import type {ISBOMDecomposition} from "../types/sbom.ts";
import SunburstChart from "../components/sunburst/sunburst-graph-test.tsx";
import {InputGroup} from "react-bootstrap";

import ComponentList from "../components/component-list/component-list.tsx";
import VulnerabilityList from "../components/vulnerability-list/vulnerability-list.tsx";
import {DecomposeSBOMFile} from "../api/sbom.ts";
import Badge from "react-bootstrap/Badge";

export default function InspectPage() {
    const [files, setFiles] = useState<Array<File>>([]);
    const [isLoading, setIsLoading] = useState<boolean>(false)

    const [onlyVulnerable, setOnlyVulnerable] = useState<boolean>(true)
    const [maxDepth, setMaxDepth] = useState<number>(12)

    const [billData, setBillData] = useState<ISBOMDecomposition | null>(null)

    const handleFileChange = (evt) => {
        console.debug(evt.target.files)

        if (evt.target.files.length > 0) {
            setFiles(evt.target.files)
        }
    }

    const handleFileUpload = async () => {
        if (files.length > 0) {
            setIsLoading(true)

            DecomposeSBOMFile(files[0], onlyVulnerable, maxDepth)
                .then(response => {
                    console.log("sbom file uploaded")
                    return response.json()
                })
                .then(data => {
                    setBillData(data)
                })
                .finally(() => {
                    setIsLoading(false)
                })
        }
    }

    useEffect(() => {
        console.debug(billData)
    }, [billData]);

    return <div className="inspect-page">
        <div id={"sbom-upload"}>
            <Form.Group controlId="sbom-upload-form" className="mb-3">
                <Form.Label>Upload CycloneDX SBOM file here</Form.Label>
                <Form.Control onChange={handleFileChange} type="file" multiple/>
            </Form.Group>
            <InputGroup className="mb-3">
                <Button disabled={isLoading || files.length === 0} variant="primary" onClick={handleFileUpload}>
                    {isLoading ? 'Loading…' : 'Upload new SBOM file'}
                </Button>

                <InputGroup.Text id="max-depth">Max depth</InputGroup.Text>
                <Form.Control
                    type={'number'}
                    value={maxDepth}
                    onChange={(evt) => {
                        setMaxDepth(parseInt(evt.target.value))
                    }}
                    placeholder="4"
                    aria-label="max-depth"
                    aria-describedby="max-depth"
                />
            </InputGroup>
            <InputGroup>
                <Form.Check // prettier-ignore
                    type="switch"
                    checked={onlyVulnerable}
                    onChange={(evt) => {
                        setOnlyVulnerable(evt.target.checked)
                    }}
                    id="only-vulnerable-components-load-switch"
                    label="Load only vulnerable components"
                />
            </InputGroup>
        </div>
        {
            billData ? <Fragment>
                <div id={"sbom-summary"}>
                    <b>SBOM summary</b>
                    <p>Total nodes count: {billData.totalNodes}</p>
                    <p>Total unique components count: {billData.components.length}</p>
                    {
                        billData.vulnerabilities.length > 0 ?
                            <details className={"total-cves"}>
                                <summary>
                                    Total CVEs count: {billData.vulnerabilities.length}
                                </summary>
                                <ul>
                                    {billData.vulnerabilities.map((vuln, i) => {
                                        return <li key={i}>{vuln.id}</li>
                                    })}
                                </ul>
                            </details>
                            :
                            <span/>
                    }
                    {
                        billData.dependencyCycles.length > 0
                            ?
                            <details className={"resolved-cycles"}>
                                <summary>
                                    Dependency cycles resolved: {billData.dependencyCycles.length}
                                </summary>
                                <ul>
                                    {billData.dependencyCycles.map((cycle, i) => {
                                        return <details key={i}>
                                            <summary>
                                                Resolved cycle #{i}
                                            </summary>
                                            <ul>
                                                {cycle.path.map((lib, j) => {
                                                    return <li key={j}>{lib}</li>
                                                })}
                                            </ul>
                                        </details>
                                    })}
                                </ul>
                            </details>
                            :
                            <span/>
                    }
                </div>
                <div id="sbom-sunburst-graph">
                    <div className={"sbom-sunburst-graph-legend"}>
                        <Badge bg={"dark"}>Critical</Badge>
                        <Badge text={"dark"} bg={"danger"}>High</Badge>
                        <Badge text={"dark"} bg={"warning"}>Medium</Badge>
                        <Badge text={"dark"} bg={"primary"}>Low</Badge>
                        <Badge text={"dark"} bg={"info"}>Info</Badge>
                        <Badge text={"dark"} bg={"secondary"}>Transitive</Badge>
                    </div>
                    <SunburstChart rootComponent={billData.graph}/>
                </div>
                <div id="sbom-sunburst-graph-filters"></div>
                {
                    billData.components.length > 0 ?
                        <div id="sbom-components-list-container">
                            <ComponentList components={billData.components}/>
                        </div>
                        :
                        <Fragment/>
                }
                {
                    billData.vulnerabilities.length > 0 ?
                        <div id="sbom-vulnerabilities-list-container">
                            <VulnerabilityList vulnerabilities={billData.vulnerabilities}/>
                        </div>
                        :
                        <Fragment/>
                }
            </Fragment> : <Fragment/>
        }

        {/*<div id="sbom-vulnerabilities-list-container">*/}
        {/*    <VulnerabilityList/>*/}
        {/*</div>*/}
    </div>
}