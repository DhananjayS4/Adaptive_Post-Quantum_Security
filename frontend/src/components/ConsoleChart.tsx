import ReactEChartsCore from "echarts-for-react/lib/core";
import * as echarts from "echarts/core";
import { BarChart } from "echarts/charts";
import {
  GridComponent,
  LegendComponent,
  TooltipComponent,
} from "echarts/components";
import { SVGRenderer } from "echarts/renderers";
import type { EChartsOption } from "echarts";

echarts.use([BarChart, GridComponent, LegendComponent, TooltipComponent, SVGRenderer]);

const text = "#95a3b7";
const grid = "#273241";
const axis = "#4a586b";

export function ConsoleChart({
  option,
  height = 260,
}: {
  option: EChartsOption;
  height?: number;
}) {
  const defaults: EChartsOption = {
    animationDuration: 250,
    backgroundColor: "transparent",
    textStyle: { color: text, fontFamily: "Inter, system-ui, sans-serif" },
    tooltip: {
      trigger: "axis",
      backgroundColor: "#101821",
      borderColor: grid,
      textStyle: { color: "#e4eaf1", fontSize: 12 },
    },
    grid: { left: 42, right: 18, top: 28, bottom: 32 },
    xAxis: {
      axisLine: { lineStyle: { color: axis } },
      axisLabel: { color: text, fontSize: 11 },
      splitLine: { show: false },
    },
    yAxis: {
      axisLine: { show: false },
      axisLabel: { color: text, fontSize: 11 },
      splitLine: { lineStyle: { color: grid, type: "dashed" } },
    },
    color: ["#28b8a7", "#5f7d9e", "#d6a84c", "#d56169"],
  };

  return (
    <ReactEChartsCore
      echarts={echarts}
      option={{ ...defaults, ...option }}
      notMerge
      style={{ height, width: "100%" }}
      opts={{ renderer: "svg" }}
    />
  );
}
