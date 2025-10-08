import {useEffect, useState} from "react";

import ReactECharts from 'echarts-for-react';
import type {IComponent} from "../../types/sbom.ts";

interface ISunburstGraphProps {
    graph: IComponent
}

interface IGraphNode {
    value: number
    children: Array<IGraphNode>
    itemStyle: {
        color: string
    }
}

export default function SunburstGraph(props: ISunburstGraphProps) {
    const [data, setData] = useState<IGraphNode>()

    const options = {
        series: {
            radius: ['15%', '80%'],
            type: 'sunburst',
            sort: undefined,
            emphasis: {
                focus: 'ancestor'
            },
            data: data,
            label: {
                rotate: 'radial'
            },
            levels: [],
            itemStyle: {
                color: '#ddd',
                borderWidth: 2
            }
        }
    };

    useEffect(() => {
        setData({
            value: 1,
            children: [],
            itemStyle: item1,
        })
    }, []);

    // @ts-ignore
    return <ReactECharts
        option={options}
        notMerge={true}
        lazyUpdate={true}
        style={{height: '100%', width: '100%'}}
        opts={{renderer: 'canvas'}}
    />
}

const item1 = {
    color: '#F54F4A'
};

const item2 = {
    color: '#FF8C75'
};

const item3 = {
    color: '#FFB499'
};