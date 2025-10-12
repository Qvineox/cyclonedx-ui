import {Fragment} from "react";
import Badge from "react-bootstrap/Badge";

export default function renderMaxSeverityCell(rating: number) {
    let bgColor = "info"
    let textColor = "dark"

    if (rating === undefined) {
        return <Fragment/>
    } else {
        if (rating >= 7.5) {
            if (rating >= 9.5) {
                bgColor = "dark"
                textColor = "white"
            } else {
                bgColor = "danger"
            }
        } else if (rating > 5) {

            bgColor = "warning"
        } else {
            bgColor = "info"
        }
    }

    return <Badge style={{textAlign: "start"}} bg={bgColor} text={textColor}>{rating}</Badge>
}