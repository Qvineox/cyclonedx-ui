export default function Navbar() {
    return <nav id={"sidebar"}>
        <a href={"#sbom-upload"}
           title={"upload new file"}
           style={{margin: "1vh 0 auto 0"}}
           className={"bi bi-upload text-white"}
        />

        <a href={"#sbom-sunburst-graph"}
           title={"return home"}
           className={"bi bi-vignette text-white"}
        />
        <a href={"#sbom-components-list-container"}
           title={"view components"}
           className={"bi bi-layers text-white"}
        />

        <a href={"#sbom-vulnerabilities-list-container"}
           title={"view vulnerabilities"}
           className={"bi bi-exclamation-triangle text-white"}
        />

        <a href={"https://github.com/Qvineox/cyclonedx-ui"}
           title={"visit github"}
           style={{margin: "auto 0 0 0"}}
           className={"bi bi-github text-white"}
        />

        <i title={"to the top"}
           className={"bi bi-arrow-up-circle text-white"}
        />
    </nav>
}