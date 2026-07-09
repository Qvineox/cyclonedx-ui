import React, {Fragment, useState} from "react";
import {CompareSBOMFiles} from "../api/sbom.ts";
import Form from "react-bootstrap/Form";
import Button from "react-bootstrap/Button";
import {InputGroup} from "react-bootstrap";
import type {ISBOMComparison} from "../types/sbom.ts";

export function ComparePage() {
    document.title = "SBOM comparison"

    const [files, setFiles] = useState<FileList>();
    const [isLoading, setIsLoading] = useState<boolean>(false)

    const [compareData, setCompareData] = useState<ISBOMComparison | null>(null)

    const handleFileChange = (evt: React.ChangeEvent<HTMLInputElement>) => {
        if (evt.target.files && evt.target.files.length == 2) {
            setFiles(evt.target.files)
        } else {
            alert("Необходимо выбрать минимум 2 файла!")
        }
    }

    const handleFilesUpload = async () => {
        if (files && files.length == 2) {
            setIsLoading(true)

            console.log("uploading file...")

            CompareSBOMFiles(files[0], files[1])
                .then(response => {
                    console.log("sbom file uploaded")
                    return response.json()
                })
                .then((data) => {
                    setCompareData(data)
                })
                .catch(() => {
                    alert("failed to process SBOM file")
                })
                .finally(() => {
                    setIsLoading(false)
                })
        }
    }

    return <div className="compare-page">
        <div id={"sbom-upload"}>
            <Form.Group controlId="sbom-upload-form-left" className="mb-3">
                <Form.Label>Upload both CycloneDX SBOM files here</Form.Label>
                <Form.Control onChange={handleFileChange} type="file" multiple/>
            </Form.Group>
            <InputGroup className="mb-3">
                <Button disabled={isLoading || files && files.length === 0} variant="primary"
                        onClick={handleFilesUpload}>
                    {isLoading ? 'Loading…' : 'Upload new SBOM files'}
                </Button>
            </InputGroup>
        </div>
        {
            compareData ? <Fragment>
                <div className={"identical-components"}>
                    <ul>
                        {compareData.identicalComponents?.map((value, index) => {
                            return <li key={index}>
                                {value.name}
                            </li>
                        })}
                    </ul>
                </div>
                <div className={"sbom-comparison sbom-comparison_left"}>
                    <ul>
                        {compareData.leftUniqueComponents?.map((value, index) => {
                            return <li className={getComponentBgColorClass(value.maxSeverity)} key={index}>
                                {value.name}
                            </li>
                        })}
                    </ul>
                </div>
                <div className={"sbom-comparison sbom-comparison_right"}>
                    <ul>
                        {compareData.rightUniqueComponents?.map((value, index) => {
                            return <li className={getComponentBgColorClass(value.maxSeverity)} key={index}>
                                {value.name}
                            </li>
                        })}
                    </ul>
                </div>
                <div id={"vulnerabilities"}></div>
            </Fragment> : <Fragment/>
        }
    </div>
}

function getComponentBgColorClass(maxSeverity: number) {
    if (maxSeverity >= 6.9) {
        if (maxSeverity >= 9.0) {
            return "critical"
        } else {
            return "high"
        }
    } else if (maxSeverity >= 4.0) {
        return "medium"
    } else if (maxSeverity >= 0.1) {
        return "low"
    }
}