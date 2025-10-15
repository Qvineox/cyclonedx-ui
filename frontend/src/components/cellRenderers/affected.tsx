import Badge from "react-bootstrap/Badge";
import Stack from "react-bootstrap/Stack";
import type {IAffect} from "../../types/sbom.ts";

export default function renderAffectedCell(data: Array<IAffect>) {
    return <Stack gap={2}>
        {data.map((value, index) => {
            return <Badge style={{textAlign: "start"}} bg={"secondary"} text={"light"} key={index}>{value.ref}</Badge>
        })}
    </Stack>
}