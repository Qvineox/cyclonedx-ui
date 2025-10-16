export async function DecomposeSBOMFile(file: File, onlyVulnerable: boolean, maxDepth: number) {
    let data: string = await blobToBase64(file)
    return fetch("http://localhost:8080/api/v1/sbom/decompose", {
        method: 'POST',
        headers: {
            'Accept': 'application/json',
            'Content-Type': 'application/json',
        },
        body: JSON.stringify({
            "only_vulnerable": onlyVulnerable,
            "max_depth": maxDepth,
            "files": [
                {
                    "data": data.split(',')[1],
                    "file_name": file.name
                }
            ]
        })
    })
}

function blobToBase64(blob: File): Promise<string> {
    return new Promise((resolve, _) => {
        const reader = new FileReader();

        reader.onloadend = () => resolve(reader.result as string);
        reader.onerror = (event) => {
            console.error("error reading file:", event.target?.error);
        };

        reader.readAsDataURL(blob);
    });
}