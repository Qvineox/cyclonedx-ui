import {Fragment} from "react";
import DataTable from 'datatables.net-react';
import type {IComponent} from "../../types/sbom.ts";

import {renderToString} from "react-dom/server";
import renderMaxSeverityCell from "../cellRenderers/max-severity.tsx";
import {useSearchParams} from "react-router-dom";

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
    {
        title: 'Actions',
        data: 'name',
        className: 'actions',
        orderable: false,
    },
]

const handleComponentSearchClick = (name) => {
    let searchParams = new URLSearchParams(window.location.search);
    searchParams.set("component", name);

    window.location.search = searchParams.toString();
}

export default function ComponentList(props: IComponentListProps) {
    const [searchParams, setSearchParams] = useSearchParams();

    const searchComponent = (name: string) => {
        let params = searchParams
        params.set("component", name)

        setSearchParams(params)
    }

    return <Fragment>
        <DataTable className={"table table-striped cell-border"}
                   columns={columns}
                   data={props.components}
                   slots={{
                       8: (data) => {
                           return <a title={"show on graph"}
                                     className={"bi bi-search text-black"}
                                     onClick={() => {
                                         searchComponent(data)
                                     }}
                           />
                       }
                   }}
                   options={{
                       autoWidth: true,
                       paging: true
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
                <th>actions</th>
            </tr>
            </thead>
        </DataTable>
    </Fragment>
}