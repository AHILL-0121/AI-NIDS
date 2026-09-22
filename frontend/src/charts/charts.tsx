"use client";

import { useCallback } from "react";

import { bitrate, count, percent } from "@/lib/format";
import type { Schemas } from "@/lib/api/client";

import { EChart, axisStyle, baseOption } from "./EChart";
import type { ChartTheme } from "./theme";

type Bucket = Schemas["Bucket"];

function timeLabel(ts: number, resolution: number): string {
  const d = new Date(ts * 1000);
  const hh = String(d.getHours()).padStart(2, "0");
  const mm = String(d.getMinutes()).padStart(2, "0");
  if (resolution >= 60) return `${hh}:${mm}`;
  return `${hh}:${mm}:${String(d.getSeconds()).padStart(2, "0")}`;
}

/** Throughput (area, bits/s) and new flows (line) with alert ticks on the time axis. */
export function TrafficChart({
  buckets,
  resolution,
  height = 240,
}: {
  buckets: Bucket[];
  resolution: 1 | 60;
  height?: number;
}) {
  const build = useCallback(
    (theme: ChartTheme) => {
      const per = resolution; // bucket length in seconds
      const alertTicks = buckets.filter((b) => b.alerts > 0);
      return {
        ...baseOption(theme),
        grid: { left: 64, right: 56, top: 28, bottom: 28 },
        legend: {
          top: 0,
          right: 0,
          icon: "rect",
          itemWidth: 10,
          itemHeight: 3,
          textStyle: { color: theme.inkMuted, fontSize: 11 },
        },
        tooltip: {
          ...(baseOption(theme).tooltip as object),
          trigger: "axis",
          valueFormatter: undefined,
        },
        xAxis: {
          type: "time",
          ...axisStyle(theme),
          splitLine: { show: false },
          axisLabel: {
            color: theme.inkSubtle,
            fontSize: 11,
            formatter: (value: number) => timeLabel(value / 1000, resolution),
            hideOverlap: true,
          },
        },
        yAxis: [
          {
            type: "value",
            ...axisStyle(theme),
            axisLabel: {
              color: theme.inkSubtle,
              fontSize: 11,
              formatter: (v: number) => bitrate(v),
            },
          },
          {
            type: "value",
            ...axisStyle(theme),
            splitLine: { show: false },
            axisLabel: {
              color: theme.inkSubtle,
              fontSize: 11,
              formatter: (v: number) => `${count(v)}/s`,
            },
          },
        ],
        series: [
          {
            name: "Throughput",
            type: "line",
            showSymbol: false,
            smooth: false,
            lineStyle: { width: 1.5, color: theme.accent },
            itemStyle: { color: theme.accent },
            areaStyle: { color: theme.accent, opacity: theme.mode === "dark" ? 0.18 : 0.1 },
            data: buckets.map((b) => [b.ts * 1000, b.bytes / per]),
            tooltip: { valueFormatter: (v: number) => bitrate(v) },
            markLine: alertTicks.length
              ? {
                  symbol: "none",
                  silent: true,
                  label: { show: false },
                  lineStyle: { color: theme.critical, type: "solid", width: 1, opacity: 0.6 },
                  data: alertTicks.slice(-40).map((b) => ({ xAxis: b.ts * 1000 })),
                }
              : undefined,
          },
          {
            name: "New flows",
            type: "line",
            yAxisIndex: 1,
            showSymbol: false,
            lineStyle: { width: 1, color: theme.series[2] },
            itemStyle: { color: theme.series[2] },
            data: buckets.map((b) => [b.ts * 1000, b.flows_started / per]),
            tooltip: { valueFormatter: (v: number) => `${v.toFixed(1)} /s` },
          },
        ],
      };
    },
    [buckets, resolution],
  );
  return (
    <EChart
      build={build}
      height={height}
      label="Traffic over time: throughput and new flows per second"
    />
  );
}

/** Minimal sparkline, no axes. */
export function Sparkline({
  values,
  label,
  height = 28,
}: {
  values: number[];
  label: string;
  height?: number;
}) {
  const build = useCallback(
    (theme: ChartTheme) => ({
      animation: false,
      grid: { left: 0, right: 0, top: 2, bottom: 2 },
      xAxis: { type: "category", show: false, data: values.map((_, i) => i) },
      yAxis: { type: "value", show: false, min: 0 },
      series: [
        {
          type: "line",
          data: values,
          showSymbol: false,
          lineStyle: { width: 1.25, color: theme.inkMuted },
          areaStyle: { color: theme.inkMuted, opacity: 0.08 },
        },
      ],
    }),
    [values],
  );
  return <EChart build={build} height={height} label={label} />;
}

/** Confusion matrix heatmap. Rows are the true class, columns the prediction; row-normalised. */
export function ConfusionHeatmap({ labels, matrix }: { labels: string[]; matrix: number[][] }) {
  const build = useCallback(
    (theme: ChartTheme) => {
      const keep = labels
        .map((_, i) => i)
        .filter(
          (i) =>
            (matrix[i]?.reduce((a, b) => a + b, 0) ?? 0) > 0 ||
            matrix.some((row) => (row[i] ?? 0) > 0),
        );
      const names = keep.map((i) => labels[i]!);
      const data: [number, number, number, number][] = [];
      keep.forEach((ti, y) => {
        const total = matrix[ti]!.reduce((a, b) => a + b, 0) || 1;
        keep.forEach((pi, x) => {
          const n = matrix[ti]![pi] ?? 0;
          data.push([x, y, n / total, n]);
        });
      });
      return {
        ...baseOption(theme),
        grid: { left: 96, right: 16, top: 8, bottom: 64 },
        tooltip: {
          ...(baseOption(theme).tooltip as object),
          formatter: (p: { value: [number, number, number, number] }) =>
            `true <b>${names[p.value[1]]}</b> → predicted <b>${names[p.value[0]]}</b><br/>${p.value[3].toLocaleString()} flows · ${percent(p.value[2])} of row`,
        },
        xAxis: {
          type: "category",
          data: names,
          name: "Predicted",
          nameLocation: "middle",
          nameGap: 48,
          ...axisStyle(theme),
          axisLabel: { color: theme.inkMuted, fontSize: 11, rotate: 30 },
          splitLine: { show: false },
        },
        yAxis: {
          type: "category",
          data: names,
          inverse: true,
          ...axisStyle(theme),
          axisLabel: { color: theme.inkMuted, fontSize: 11 },
          splitLine: { show: false },
        },
        visualMap: {
          show: false,
          min: 0,
          max: 1,
          dimension: 2,
          inRange: { color: [theme.surfaceSunken, theme.accent] },
        },
        series: [
          {
            type: "heatmap",
            data,
            label: {
              show: true,
              fontSize: 10,
              fontFamily: theme.fontMono,
              formatter: (p: { value: [number, number, number, number] }) =>
                p.value[3] === 0 ? "" : percent(p.value[2], 0),
              color: theme.ink,
            },
            itemStyle: { borderColor: theme.surface, borderWidth: 1 },
          },
        ],
      };
    },
    [labels, matrix],
  );
  const size = Math.max(240, Math.min(labels.length, 10) * 36 + 80);
  return <EChart build={build} height={size} label="Confusion matrix, rows are the true class" />;
}

export interface SweepPoint {
  threshold: number;
  precision: number;
  recall: number;
  false_positive_rate: number;
}

/** Precision and recall against the attack-probability threshold, with the operating point marked. */
export function ThresholdCurve({ points, operating }: { points: SweepPoint[]; operating: number }) {
  const build = useCallback(
    (theme: ChartTheme) => ({
      ...baseOption(theme),
      grid: { left: 48, right: 16, top: 28, bottom: 36 },
      legend: {
        top: 0,
        right: 0,
        icon: "rect",
        itemWidth: 10,
        itemHeight: 3,
        textStyle: { color: theme.inkMuted },
      },
      tooltip: {
        ...(baseOption(theme).tooltip as object),
        trigger: "axis",
        valueFormatter: (v: number) => percent(v),
      },
      xAxis: {
        type: "value",
        min: 0,
        max: 1,
        name: "Threshold",
        nameLocation: "middle",
        nameGap: 24,
        ...axisStyle(theme),
      },
      yAxis: {
        type: "value",
        min: 0,
        max: 1,
        ...axisStyle(theme),
        axisLabel: { formatter: (v: number) => percent(v, 0), color: theme.inkSubtle },
      },
      series: [
        {
          name: "Precision",
          type: "line",
          data: points.map((p) => [p.threshold, p.precision]),
          symbolSize: 4,
          lineStyle: { color: theme.accent, width: 1.5 },
          itemStyle: { color: theme.accent },
          markLine: {
            symbol: "none",
            label: { formatter: "operating point", color: theme.inkMuted, fontSize: 10 },
            lineStyle: { color: theme.inkMuted, type: "dashed" },
            data: [{ xAxis: operating }],
          },
        },
        {
          name: "Recall",
          type: "line",
          data: points.map((p) => [p.threshold, p.recall]),
          symbolSize: 4,
          lineStyle: { color: theme.series[2], width: 1.5 },
          itemStyle: { color: theme.series[2] },
        },
        {
          name: "False-positive rate",
          type: "line",
          data: points.map((p) => [p.threshold, p.false_positive_rate]),
          symbolSize: 3,
          lineStyle: { color: theme.critical, width: 1, type: "dotted" },
          itemStyle: { color: theme.critical },
        },
      ],
    }),
    [points, operating],
  );
  return (
    <EChart
      build={build}
      height={260}
      label="Precision, recall and false-positive rate by threshold"
    />
  );
}
