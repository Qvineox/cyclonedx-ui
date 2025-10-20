CDXGEN_SBOM_FILE_NAME=cdxgen_report.cdx.json

TRIVY_REPORT_FILE_NAME=trivy_report.json
TRIVY_SBOM_FILE_NAME=trivy_report.cdx.json

# run cdxgen to build composite SBOM file for this project
docker run --rm -e CDXGEN_DEBUG_MODE=debug -e GOMODCACHE=/tmp/go -v /tmp:/tmp -v $(pwd):/app:rw -t ghcr.io/cyclonedx/cdxgen:latest --deep --install-deps true --max-old-space-size 8196 --fail-on-error -r /app -o /app/bom.cdx.json

# detect vulnerabilities in SBOM file with Trivy
docker run --rm -v /tmp:/tmp -v $(pwd):/app:rw -t aquasec/trivy:latest sbom --scanners vuln,license --detection-priority comprehensive --format cyclonedx --output /app/trivy_bom.cdx.json /app/bom.cdx.json

# convert Trivy report to SBOM file
docker run --rm -v /tmp:/tmp -v $(pwd):/app:rw -t aquasec/trivy:latest convert --format cyclonedx --output /app/${TRIVY_SBOM_FILE_NAME} /app/${TRIVY_REPORT_FILE_NAME}

# using depscan
docker run --rm -v /tmp:/tmp -v $(pwd):/app:rw -t  ghcr.io/owasp-dep-scan/dep-scan depscan --src /app --reports-dir /app/reports/depscan

sudo docker run --rm -v /tmp:/tmp -v $(pwd):/app:rw -t ghcr.io/cyclonedx/cdxgen:latest --resolve-class --evidence --required-only --deep --install-deps true --max-old-space-size 8196 --fail-on-error -r /app/jar/file.jar -o /app/jar_bom.evidence-class-required.cdx.json