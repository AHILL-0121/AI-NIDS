"use client";

/** Data hooks: one place that knows every endpoint and cache key. */
import { keepPreviousData, useMutation, useQuery, useQueryClient } from "@tanstack/react-query";

import { client, unwrap, type Schemas } from "@/lib/api/client";

export type Alert = Schemas["AlertOut"];
export type Flow = Schemas["FlowOut"];
export type Session = Schemas["SessionOut"];
export type Job = Schemas["JobOut"];
export type ModelInfo = Schemas["ModelOut"];
export type RuntimeSettings = Schemas["RuntimeSettings"];
export type Severity = Alert["severity"];
export type AlertStatus = Alert["status"];

export interface AlertFilters {
  severity?: Severity[];
  status?: AlertStatus[];
  type?: string[];
  src?: string;
  dst?: string;
  since?: number;
  session_id?: string;
  limit?: number;
  offset?: number;
}

export function useAlerts(filters: AlertFilters) {
  return useQuery({
    queryKey: ["alerts", filters],
    queryFn: () => unwrap(client.GET("/api/alerts", { params: { query: filters } })),
    placeholderData: keepPreviousData,
  });
}

export function useAlert(id: string | null) {
  return useQuery({
    queryKey: ["alert", id],
    queryFn: () =>
      unwrap(client.GET("/api/alerts/{alert_id}", { params: { path: { alert_id: id! } } })),
    enabled: Boolean(id),
  });
}

export function useUpdateAlert() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: ({ id, status, note }: { id: string; status?: AlertStatus; note?: string }) =>
      unwrap(
        client.PATCH("/api/alerts/{alert_id}", {
          params: { path: { alert_id: id } },
          body: { status: status ?? null, note: note ?? null },
        }),
      ),
    onSuccess: (alert) => {
      queryClient.setQueryData(["alert", alert.id], alert);
      void queryClient.invalidateQueries({ queryKey: ["alerts"] });
      void queryClient.invalidateQueries({ queryKey: ["summary"] });
      void queryClient.invalidateQueries({ queryKey: ["suppressions"] });
    },
  });
}

export function useSummary() {
  return useQuery({
    queryKey: ["summary"],
    queryFn: () => unwrap(client.GET("/api/stats/summary")),
  });
}

/** Traffic buckets for the last `span` seconds (or since `since` for replays with old timestamps). */
export function useTimeseries(params: {
  resolution: 1 | 60;
  span?: number;
  since?: number;
  session_id?: string;
  refetchInterval?: number;
}) {
  const { resolution, span = 900, since, session_id, refetchInterval } = params;
  return useQuery({
    queryKey: ["timeseries", resolution, span, since ?? null, session_id ?? null],
    queryFn: () =>
      unwrap(
        client.GET("/api/stats/timeseries", {
          params: { query: { resolution, since: since ?? Date.now() / 1000 - span, session_id } },
        }),
      ),
    refetchInterval,
  });
}

export function useSensor() {
  return useQuery({
    queryKey: ["sensor", "status"],
    queryFn: () => unwrap(client.GET("/api/sensor/status")),
    refetchInterval: 15_000, // safety net; the WebSocket normally triggers refreshes
  });
}

export function useCapabilities() {
  return useQuery({
    queryKey: ["sensor", "capabilities"],
    queryFn: () => unwrap(client.GET("/api/sensor/capabilities")),
    staleTime: 60_000,
  });
}

export function useInterfaces(enabled = true) {
  return useQuery({
    queryKey: ["sensor", "interfaces"],
    queryFn: () => unwrap(client.GET("/api/sensor/interfaces")),
    enabled,
    staleTime: 60_000,
  });
}

export function useSensorControl() {
  const queryClient = useQueryClient();
  const refresh = () => {
    void queryClient.invalidateQueries({ queryKey: ["sensor"] });
    void queryClient.invalidateQueries({ queryKey: ["sessions"] });
  };
  const start = useMutation({
    mutationFn: (body: Schemas["StartSensor"]) =>
      unwrap(client.POST("/api/sensor/start", { body })),
    onSuccess: refresh,
  });
  const stop = useMutation({
    mutationFn: () => unwrap(client.POST("/api/sensor/stop")),
    onSuccess: refresh,
  });
  return { start, stop };
}

export function useSessions(limit = 50) {
  return useQuery({
    queryKey: ["sessions", limit],
    queryFn: () => unwrap(client.GET("/api/sessions", { params: { query: { limit } } })),
  });
}

export interface FlowFilters {
  session_id?: string;
  ip?: string;
  port?: number;
  protocol?: number;
  flow_id?: string[];
  since?: number;
  limit?: number;
  offset?: number;
}

export function useFlows(filters: FlowFilters, enabled = true) {
  return useQuery({
    queryKey: ["flows", filters],
    queryFn: () => unwrap(client.GET("/api/flows", { params: { query: filters } })),
    enabled,
    placeholderData: keepPreviousData,
  });
}

export function useModels() {
  return useQuery({ queryKey: ["models"], queryFn: () => unwrap(client.GET("/api/models")) });
}

export function useModelReport(version: string | null) {
  return useQuery({
    queryKey: ["models", "report", version],
    queryFn: () =>
      unwrap(
        client.GET("/api/models/{version}/report", { params: { path: { version: version! } } }),
      ),
    enabled: Boolean(version),
    staleTime: Infinity,
  });
}

export function useModelActivation() {
  const queryClient = useQueryClient();
  const refresh = () => {
    void queryClient.invalidateQueries({ queryKey: ["models"] });
    void queryClient.invalidateQueries({ queryKey: ["sensor"] });
  };
  const activate = useMutation({
    mutationFn: (version: string) =>
      unwrap(client.POST("/api/models/{version}/activate", { params: { path: { version } } })),
    onSuccess: refresh,
  });
  const deactivate = useMutation({
    mutationFn: () => unwrap(client.POST("/api/models/deactivate")),
    onSuccess: refresh,
  });
  return { activate, deactivate };
}

export function useSettings() {
  return useQuery({ queryKey: ["settings"], queryFn: () => unwrap(client.GET("/api/settings")) });
}

export function useUpdateSettings() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: (changes: Partial<RuntimeSettings>) =>
      unwrap(client.PATCH("/api/settings", { body: changes as Record<string, unknown> })),
    onSuccess: (data) => queryClient.setQueryData(["settings"], data),
  });
}

export function useSuppressions() {
  return useQuery({
    queryKey: ["suppressions"],
    queryFn: () => unwrap(client.GET("/api/suppressions")),
  });
}

export function useAddSuppression() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: (body: Schemas["RuleIn"]) => unwrap(client.POST("/api/suppressions", { body })),
    onSuccess: () => void queryClient.invalidateQueries({ queryKey: ["suppressions"] }),
  });
}

export function useDisableSuppression() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: (id: number) =>
      unwrap(client.DELETE("/api/suppressions/{rule_id}", { params: { path: { rule_id: id } } })),
    onSuccess: () => void queryClient.invalidateQueries({ queryKey: ["suppressions"] }),
  });
}

export function useJobs() {
  return useQuery({ queryKey: ["jobs"], queryFn: () => unwrap(client.GET("/api/jobs")) });
}

export function useStartJob() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: (body: Schemas["ReplayJob"] | Schemas["TrainJob"] | Schemas["PrepareJob"]) =>
      unwrap(client.POST("/api/jobs", { body })),
    onSuccess: () => void queryClient.invalidateQueries({ queryKey: ["jobs"] }),
  });
}

export function useCancelJob() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: (id: string) =>
      unwrap(client.POST("/api/jobs/{job_id}/cancel", { params: { path: { job_id: id } } })),
    onSuccess: () => void queryClient.invalidateQueries({ queryKey: ["jobs"] }),
  });
}

export function useUploads() {
  return useQuery({ queryKey: ["uploads"], queryFn: () => unwrap(client.GET("/api/uploads")) });
}

export function useUploadPcap() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: (file: File) =>
      unwrap(
        client.POST("/api/uploads", {
          body: { file: file as unknown as string },
          bodySerializer: (body) => {
            const form = new FormData();
            form.append("file", body.file as unknown as Blob, file.name);
            return form;
          },
        }),
      ),
    onSuccess: () => void queryClient.invalidateQueries({ queryKey: ["uploads"] }),
  });
}

export function useLogs(source: string, lines = 200) {
  return useQuery({
    queryKey: ["logs", source, lines],
    queryFn: () => unwrap(client.GET("/api/logs", { params: { query: { source, lines } } })),
    refetchInterval: 5_000,
  });
}

export function useAudit(limit = 50) {
  return useQuery({
    queryKey: ["audit", limit],
    queryFn: () => unwrap(client.GET("/api/audit", { params: { query: { limit } } })),
  });
}

export function useChangePassword() {
  return useMutation({
    mutationFn: (body: Schemas["PasswordChange"]) =>
      unwrap(client.POST("/api/auth/password", { body })),
  });
}
