"use client";

import { BarChart, HeatmapChart, LineChart } from "echarts/charts";
import {
  AriaComponent,
  GridComponent,
  LegendComponent,
  MarkLineComponent,
  TooltipComponent,
  VisualMapComponent,
} from "echarts/components";
import { init, use as register, type EChartsCoreOption, type EChartsType } from "echarts/core";
import { SVGRenderer } from "echarts/renderers";
import { useEffect, useRef } from "react";

import { Skeleton } from "@/components/States";

import { useChartTheme, type ChartTheme } from "./theme";

// Only what the app draws: keeps the bundle small (tree-shaken ECharts).
register([
  LineChart,
  BarChart,
  HeatmapChart,
  GridComponent,
  TooltipComponent,
  LegendComponent,
  MarkLineComponent,
  VisualMapComponent,
  AriaComponent,
  SVGRenderer,
]);

/** Shared axis/tooltip styling. */
export function baseOption(theme: ChartTheme): EChartsCoreOption {
  return {
    animationDuration: 200,
    aria: { enabled: true },
    textStyle: { fontFamily: theme.fontSans, color: theme.inkMuted, fontSize: 11 },
    color: theme.series,
    tooltip: {
      backgroundColor: theme.surface,
      borderColor: theme.line,
      textStyle: { color: theme.ink, fontSize: 12 },
      extraCssText: "box-shadow: var(--shadow-float); border-radius: 6px;",
    },
  };
}

export function axisStyle(theme: ChartTheme) {
  return {
    axisLine: { lineStyle: { color: theme.line } },
    axisTick: { show: false },
    axisLabel: { color: theme.inkSubtle, fontSize: 11 },
    splitLine: { lineStyle: { color: theme.line, type: "dashed" as const } },
  };
}

/**
 * One ECharts instance. `build` turns the current theme into an option; it runs again when the
 * theme or its inputs change, so charts re-theme without a reload (design §5.8).
 */
export function EChart({
  build,
  height,
  label,
  onReady,
}: {
  build: (theme: ChartTheme) => EChartsCoreOption;
  height: number;
  label: string;
  onReady?: (chart: EChartsType) => void;
}) {
  const theme = useChartTheme();
  const host = useRef<HTMLDivElement>(null);
  const chart = useRef<EChartsType | null>(null);

  useEffect(() => {
    if (!host.current || !theme) return;
    const instance = init(host.current, undefined, { renderer: "svg" });
    chart.current = instance;
    onReady?.(instance);
    const observer = new ResizeObserver(() => instance.resize());
    observer.observe(host.current);
    return () => {
      observer.disconnect();
      instance.dispose();
      chart.current = null;
    };
    // The instance lives as long as the element; option changes are applied below.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [theme === null]);

  useEffect(() => {
    if (theme && chart.current) chart.current.setOption(build(theme), { notMerge: true });
  }, [theme, build]);

  if (!theme) return <Skeleton className="w-full" />;
  return <div ref={host} role="img" aria-label={label} style={{ height }} className="w-full" />;
}
