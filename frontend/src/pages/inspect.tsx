import Form from 'react-bootstrap/Form';
import Button from 'react-bootstrap/Button';
import {Fragment, useState} from "react";
import {DecomposeSBOMFile} from "../api/sbom.ts"
import type {ISBOMDecomposition} from "../types/sbom.ts";
import SunburstChart from "../components/sunburst/sunburst-graph-test.tsx";
import {InputGroup} from "react-bootstrap";

export default function InspectPage() {
    const [files, setFiles] = useState<Array<File>>([]);
    const [isLoading, setIsLoading] = useState<boolean>(false)

    const [billData, setBillData] = useState<ISBOMDecomposition | null>(null)

    const handleFileChange = (evt) => {
        console.debug(evt.target.files)

        if (evt.target.files.length > 0) {
            setFiles(evt.target.files)
        }
    }

    const handleFileUpload = () => {
        if (files.length > 0) {
            setIsLoading(true)

            DecomposeSBOMFile(files[0])
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

    return <div className="inspect-page">
        <div className="sbom-upload-form">
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
                    placeholder="4"
                    aria-label="max-depth"
                    aria-describedby="max-depth"
                />
            </InputGroup>
            <InputGroup>
                <Form.Check // prettier-ignore
                    type="switch"
                    id="only-vulnerable-components-load-switch"
                    label="Load only vulnerable components"
                />
                <Form.Check // prettier-ignore
                    type="switch"
                    id="compact-vulnerabilities-switch"
                    label="Merge vulnerabilities deeper then max depth"
                />
            </InputGroup>
        </div>
        {
            billData ? <Fragment>
                <div className="sbom-summary">
                    <b>SBOM summary</b>
                    <p>Total nodes count: {billData.totalNodes}</p>
                    <p>Total CVEs count: {billData.vulnerabilities.length}</p>
                </div>
                <div className="sbom-sunburst-graph">
                    <SunburstChart rootComponent={billData.graph}/>
                </div>
                <div className="sbom-sunburst-graph-filters"></div>
                <div className="sbom-components-list-container"></div>
                <div className="sbom-vulnerabilities-list-container"></div>
            </Fragment> : <Fragment/>
        }
    </div>
}