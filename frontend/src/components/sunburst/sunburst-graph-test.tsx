import React, {useMemo} from 'react';
import ReactECharts from 'echarts-for-react';
import type {IComponent} from "../../types/sbom.ts";

interface SunburstChartProps {
    rootComponent: IComponent;
    onNodeClick?: (component: IComponent) => void;
}

const maxLevelsToShow: number = 12;

const SunburstChart: React.FC<SunburstChartProps> = ({rootComponent, onNodeClick}) => {
    const chartData = useMemo(() => {
        const convertToSunburstData = (component: IComponent, depth: number = 0): any => {
            const vulnerabilityCount = component.vulnerabilities?.length || 0;

            let children

            if (depth <= maxLevelsToShow) {
                children = component.children?.map((child: IComponent) =>
                    convertToSunburstData(child, depth + 1)
                ) || [];
            }

            return {
                name: component.name,
                value: calculateNodeValue(component), // Размер сектора основан на количестве потомков
                itemStyle: {
                    color: getNodeColor(component),
                    borderColor: "#000000",
                    borderWidth: 0.5,
                    shadowBlur: 1,
                    shadowColor: "#000000"
                },
                children: children,
                tooltip: {
                    formatter: () => generateTooltip(component, depth, vulnerabilityCount)
                },
                label: {
                    formatter: (params: any) => formatLabel(params, component)
                }
            };
        };

        return convertToSunburstData(rootComponent);
    }, [rootComponent]);

    const option = useMemo(() => {
        if (!chartData) return {};

        return {
            tooltip: {
                confine: true,
                appendToBody: true,
                trigger: 'item',
                backgroundColor: 'rgba(255, 255, 255, 0.95)',
                borderColor: '#ddd',
                borderWidth: 1,
                formatter: (params: any) => {
                    return params.data.tooltip?.formatter(params) || params.name;
                }
            },
            series: {
                type: 'sunburst',
                data: [chartData],
                radius: [0, '100%'],
                label: {
                    rotate: 0,
                    align: 'center',
                    minAngle: 10,
                    fontSize: 8,
                    color: '#333'
                },
                emphasis: {
                    focus: 'ancestor',
                    itemStyle: {
                        shadowBlur: 20,
                        shadowColor: 'rgba(0, 0, 0, 0.3)',
                        borderWidth: 2
                    },
                    label: {
                        show: true,
                        fontWeight: 'bold',
                        fontSize: 10
                    }
                },
                animation: true,
                animationDuration: 1000,
                animationEasing: 'cubicOut',
                selectedMode: false
            }
        };
    }, [chartData, rootComponent]);

    const handleChartClick = (params: any) => {
        console.debug(params)

        if (onNodeClick && params.data) {
            const findComponent = (current: IComponent): IComponent | null => {
                if (current.name === params.data.name &&
                    current.type === getTypeFromColor(params.data.itemStyle?.color)) {
                    return current;
                }

                for (const child of current.children || []) {
                    const found = findComponent(child);
                    if (found) return found;
                }

                return null;
            };

            const component = findComponent(rootComponent);
            if (component) {
                onNodeClick(component);
            }
        }
    };

    const chartEvents = {
        click: handleChartClick
    };

    if (!chartData) {
        return (
            <div style={{
                display: 'flex',
                justifyContent: 'center',
                alignItems: 'center',
                color: '#666',
                fontSize: '16px',
                backgroundColor: '#fafafa',
                borderRadius: '8px'
            }}>
                No component data available for visualization
            </div>
        );
    }

    return (
        <div className={"sbom-sunburst-graph-canvas"} style={{width: '100%', height: '100%'}}>
            <ReactECharts
                option={option}
                style={{height: '100%', width: '100%'}}
                onEvents={chartEvents}
                lazyUpdate={true}
                opts={{renderer: 'canvas'}}
            />
        </div>
    );
};

const formatLabel = (params: any, component: IComponent): string => {
    const maxLength = params.depth <= 3 ? 25 : 15;
    let label = component.name;

    if (label.length > maxLength) {
        label = label.substring(0, maxLength - 3) + '...';
    }

    return label;
};

const truncateText = (text: string, maxLength: number): string => {
    if (text.length <= maxLength) return text;
    return text.substring(0, maxLength - 3) + '...';
};

const generateTooltip = (component: IComponent, depth: number, vulnCount: number): string => {

    let cves: string = "<ul>"
    component.vulnerabilities.forEach((value) => {
        cves += `<li>${value.id} (${value.maxRating})</li>`
    })
    cves += "</ul>"

    return `
        <div style="padding: 12px; min-width: 300px; font-family: Arial, sans-serif;">
          <div style="font-weight: bold; font-size: 14px; margin-bottom: 8px; color: #333;">
            ${component.name}
            
            ${vulnCount > 0 ?
        `<span style="color: #ff4d4f; margin-left: 8px; font-size: 12px;">
                        (${vulnCount} vulnerability${vulnCount > 1 ? 'ies' : ''})
                      </span>`
        :
        ''
    }
          </div>
          
          <div style="font-size: 12px; color: #666; line-height: 1.5;">
            <div><strong>Version:</strong> ${component.version || 'N/A'}</div>
            <div><strong>Type:</strong> ${component.type}</div>
            <div><strong>Group:</strong> ${component.group || 'N/A'}</div>
            <div><strong>Level:</strong> ${component.level}</div>
            <div><strong>Max severity:</strong> ${component.maxSeverity}</div>
            <div><strong>Total CVEs:</strong> ${component.totalCveCount}</div>
            <div><strong>Children:</strong> ${component.children?.length || 0}</div>
            
            ${component.description ?
        `<div style="margin-top: 6px;">
                <strong>Description:</strong> ${truncateText(component.description, 120)}
            </div>` :
        ''
    }
            
    ${
        component.vulnerabilities.length > 0 ? `<br/>Vulnerabilities: ${cves}` : `<span/>`
    }
            
            <div style="margin-top: 6px; font-size: 11px; color: #999;">
              <strong>BOM Ref:</strong> ${component.bomRef}
            </div>
          </div>
        </div>
      `;
};

const getNodeColor = (component: IComponent): string => {
    switch (component.type) {
        case 'application':
        case 'file':
            return "#d9d9d9"
        case 'library':
            if (component.vulnerabilities.length > 0) {
                const rating = component.vulnerabilities[0].maxRating
                if (rating >= 7.5) {
                    if (rating >= 9.5) {
                        return "#701617F2"
                    } else {
                        return "#F44949B5"
                    }
                } else if (rating > 5) {
                    return "#ED9757FF"
                } else if (rating > 2.5) {
                    return "#98D89BFF"
                } else {
                    return "#5799E4FF"
                }
            } else if (component.hasTransitiveVulns) {
                return "#D8BC81FF"
            }
    }


    return "#b8b0b0"
}

// Вспомогательная функция для получения типа из цвета
const getTypeFromColor = (color: string): string => {
    const colorMap: { [key: string]: string } = {
        '#1890ff': 'application',
        '#52c41a': 'library',
        '#faad14': 'framework',
        '#722ed1': 'container',
        '#13c2c2': 'operating-system',
        '#eb2f96': 'device',
        '#a0d911': 'firmware',
        '#fa8c16': 'file'
    };

    return colorMap[color] || 'unknown';
};

const calculateNodeValue = (component: IComponent): number => {
    if (!component.children || component.children.length === 0) return 1;

    let totalDescendants = 0;
    const countDescendants = (node: IComponent) => {
        totalDescendants++;
        node.children?.forEach(child => countDescendants(child));
    };

    component.children.forEach(child => countDescendants(child));
    return Math.max(totalDescendants, 1);
};

export default SunburstChart;