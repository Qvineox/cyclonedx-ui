interface ISBOMUploadRequest {
    file_name: string
    data: Array<byte>
}

export async function DecomposeSBOMFile(file: File) {
    const reader = new FileReader();

    let data = await blobToBase64(file)
    return fetch("http://localhost:8080/api/v1/sbom/decompose", {
        method: 'POST',
        headers: {
            'Accept': 'application/json',
            'Content-Type': 'application/json',
        },
        body: JSON.stringify({
            "data": data.split(',')[1],
            "file_name": file.name
        })
    })
}

function blobToBase64(blob) {
    return new Promise((resolve, _) => {
        const reader = new FileReader();

        reader.onloadend = () => resolve(reader.result);
        reader.onerror = (event) => {
            console.error("error reading file:", event.target.error);
        };

        reader.readAsDataURL(blob);
    });
}