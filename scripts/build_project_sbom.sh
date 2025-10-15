CDXGEN_SBOM_FILE_NAME=cdxgen_report.cdx.json

TRIVY_REPORT_FILE_NAME=trivy_report.json
TRIVY_SBOM_FILE_NAME=trivy_report.cdx.json

# run cdxgen to build composite SBOM file for this project
docker run --rm \
  -v /tmp:/tmp \
  -v $(pwd):/app:rw \
  -t ghcr.io/cyclonedx/cdxgen:latest --install-deps true --max-old-space-size 8196 --fail-on-error -r /app -o /app/${SBOM_FILE_NAME}

# detect vulnerabilities in SBOM file with Trivy
docker run --rm \
  -v /tmp:/tmp \
  -v $(pwd):/app:rw \
  -t aquasec/trivy:latest --scanners vuln,license --detection-priority comprehensive --format json --output /app/${TRIVY_REPORT_FILE_NAME} sbom /app/${CDXGEN_SBOM_FILE_NAME}

# convert Trivy report to SBOM file
docker run --rm \
  -v /tmp:/tmp \
  -v $(pwd):/app:rw \
  -t aquasec/trivy:latest convert --format cyclonedx --output /app/${TRIVY_SBOM_FILE_NAME} /app/${TRIVY_REPORT_FILE_NAME}