import {Fragment} from "react";
import Badge from "react-bootstrap/Badge";

export default function renderMaxSeverityCell(rating: number) {
    let bgColor = "info"
    let textColor = "dark"

    if (rating === undefined) {
        return <Fragment/>
    } else {
        if (rating >= 6.9) {
            if (rating >= 9.0) {
                bgColor = "dark"
                textColor = "white"
            } else {
                bgColor = "danger"
            }
        } else if (rating >= 4.0) {
            bgColor = "warning"
        } else if (rating >= 0.1) {
            return "success"
        } else {
            bgColor = "info"
        }
    }

    return <Badge style={{textAlign: "start"}} bg={bgColor} text={textColor}>{rating}</Badge>
}