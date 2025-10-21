import type {IDecomposeOptions} from "../types/sbom.ts";

export async function DecomposeSBOMFile(file: File, onlyVulnerable: boolean, maxDepth: number): Promise<Response> {
    const data: string = await blobToBase64(file)
    return fetch((import.meta.env.VITE_BACKEND_HOST || "") + "/api/v1/sbom/decompose", {
        method: 'POST',
        headers: {
            'Accept': 'application/json',
            'Content-Type': 'application/json',
        },
        body: JSON.stringify({
            onlyVulnerable: onlyVulnerable,
            maxDepth: maxDepth,
            upload: {
                files: [
                    {
                        data: data.split(',')[1],
                        fileName: file.name
                    }
                ]
            }
        } as IDecomposeOptions)
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