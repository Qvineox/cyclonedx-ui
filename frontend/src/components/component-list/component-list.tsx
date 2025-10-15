import {Fragment} from "react";

import DataTable from 'datatables.net-react';
import type {IComponent} from "../../types/sbom.ts";

import {renderToString} from "react-dom/server";
import renderMaxSeverityCell from "../cellRenderers/max-severity.tsx";

interface IComponentListProps {
    components: IComponent[]
}

const columns = [
    {data: 'name', title: 'Name', type: 'string', width: '30%'},
    {data: 'group', title: 'Group', type: 'string'},
    {data: 'type', title: 'Type', type: 'string'},
    {data: 'version', title: 'Version', type: 'string'},
    {data: 'level', title: 'Depth', type: 'string'},
    {data: 'hasTransitiveVulns', title: 'Transitives', type: 'boolean'},
    {
        data: 'maxSeverity',
        title: 'Max severity',
        width: '7%',
        render(data: number) {
            return renderToString(renderMaxSeverityCell(data));
        },
    },
    {data: 'totalCveCount', title: 'Total CVEs', type: 'string'},
]

export default function ComponentList(props: IComponentListProps) {
    return <Fragment>
        <DataTable className={"table table-striped"}
                   columns={columns}
                   data={props.components}
                   options={{
                       autoWidth: true,
                       paging: true,
                   }}>
            <thead>
            <tr>
                <th>name</th>
                <th>group</th>
                <th>type</th>
                <th>version</th>
                <th>level</th>
                <th>hasTransitiveVulns</th>
                <th>maxSeverity</th>
                <th>totalCveCount</th>
            </tr>
            </thead>
        </DataTable>
    </Fragment>
}