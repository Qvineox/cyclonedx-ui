import Badge from "react-bootstrap/Badge";
import Stack from "react-bootstrap/Stack";

export default function renderAffectedCell(data: Array<IAffect>, row) {
    return <Stack gap={2}>
        {data.map((value, index) => {
            return <Badge style={{textAlign: "start"}} bg={"secondary"} text={"light"} key={index}>{value.ref}</Badge>
        })}
    </Stack>
}