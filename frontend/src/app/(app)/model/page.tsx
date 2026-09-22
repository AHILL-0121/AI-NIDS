"use client";

import { BrainIcon, CheckCircleIcon } from "@phosphor-icons/react";
import { useState } from "react";

import { Tag } from "@/components/Badges";
import { Button, TextLink } from "@/components/Button";
import { cx } from "@/components/cx";
import { Select } from "@/components/Field";
import { Facts, Kpi, PageHeader, Panel } from "@/components/Panel";
import { EmptyState, ErrorState, FormError, QueryView, SkeletonRows } from "@/components/States";
import { useToast } from "@/components/Toast";
import { ConfusionHeatmap, ThresholdCurve } from "@/charts/charts";
import { absoluteTime, count, humanize, percent } from "@/lib/format";
import { useModelActivation, useModelReport, useModels, type ModelInfo } from "@/lib/queries";

import { asReport, type ModelReport } from "./report";

function fixed(value: number | null | undefined, digits = 3): string {
  return value === null || value === undefined ? "—" : value.toFixed(digits);
}

export default function ModelPage() {
  const models = useModels();
  const [chosen, setChosen] = useState<string | null>(null);
  const list = models.data ?? [];
  const version = chosen ?? list.find((m) => m.active)?.version ?? list[0]?.version ?? null;
  const model = list.find((m) => m.version === version) ?? null;

  return (
    <>
      <PageHeader
        title="Model"
        description="How the active detector performs on data it never saw during training, and which model is running."
        actions={
          list.length > 0 && (
            <Select
              label="Model version"
              hideLabel
              value={version}
              onChange={setChosen}
              className="w-80"
              options={list.map((m) => ({
                id: m.version,
                label: m.version,
                description: [m.active && "active", absoluteTime(m.created_at)]
                  .filter(Boolean)
                  .join(" · "),
              }))}
            />
          )
        }
      />
      <QueryView
        query={models}
        empty={(l) =>
          l.length === 0 ? (
            <Panel>
              <EmptyState icon={BrainIcon} title="No trained models">
                The rule-based detectors run without one. Train a model from{" "}
                <TextLink href="/jobs/">Jobs</TextLink> after downloading a dataset (see{" "}
                <span className="font-mono">backend/data/README.md</span>).
              </EmptyState>
            </Panel>
          ) : null
        }
      >
        {() => model && <ModelView key={model.version} model={model} />}
      </QueryView>
    </>
  );
}

function ModelView({ model }: { model: ModelInfo }) {
  const report = useModelReport(model.version);
  const { activate, deactivate } = useModelActivation();
  const notify = useToast();

  return (
    <>
      <Panel
        title="Deployment"
        actions={
          model.active ? (
            <Button
              size="dense"
              loading={deactivate.isPending}
              onPress={() =>
                deactivate.mutate(undefined, {
                  onSuccess: () => notify("Model turned off; rules only.", { tone: "ok" }),
                })
              }
            >
              Turn off
            </Button>
          ) : (
            <Button
              size="dense"
              variant="primary"
              loading={activate.isPending}
              onPress={() =>
                activate.mutate(model.version, {
                  onSuccess: () =>
                    notify(`${model.version} is active. Running captures pick it up on restart.`, {
                      tone: "ok",
                    }),
                })
              }
            >
              Activate
            </Button>
          )
        }
        bodyClassName="p-4 flex flex-col gap-3"
      >
        <Facts
          columns={3}
          items={[
            [
              "Status",
              model.active ? (
                <span className="inline-flex items-center gap-1 text-ok">
                  <CheckCircleIcon size={14} weight="fill" aria-hidden /> Active
                </span>
              ) : (
                "Not active"
              ),
            ],
            ["Dataset", model.dataset ?? "—"],
            ["Split", model.protocol ?? "—"],
            ["Features", model.feature_set ?? "—"],
            ["Trained", absoluteTime(model.created_at)],
            [
              "Version",
              <span key="v" className="font-mono text-dense">
                {model.version}
              </span>,
            ],
          ]}
        />
        <FormError error={activate.error ?? deactivate.error} />
      </Panel>

      {report.isPending ? (
        <SkeletonRows rows={8} />
      ) : report.error ? (
        <ErrorState error={report.error} onRetry={() => void report.refetch()} />
      ) : (
        <ReportView report={asReport(report.data)} />
      )}
    </>
  );
}

function ReportView({ report }: { report: ModelReport }) {
  const rule = report.binary?.alert_rule ?? report.binary?.supervised;
  const supervised = report.binary?.supervised;
  const novelty = report.binary?.novelty;
  const perClass = Object.entries(report.multiclass?.per_class ?? {}).filter(
    ([, m]) => m.support > 0,
  );
  const families = Object.entries(report.per_family ?? {});
  const known = report.multiclass?.known_families ?? [];
  const matrix = report.multiclass?.confusion_matrix;

  return (
    <>
      <section
        aria-label="Test-set metrics"
        className="grid grid-cols-2 rounded-[var(--radius-panel)] border border-line bg-surface sm:grid-cols-3 lg:grid-cols-6 lg:divide-x lg:divide-line"
      >
        <Kpi
          label="Alert precision"
          value={percent(rule?.precision)}
          detail="alerts that were attacks"
        />
        <Kpi label="Recall" value={percent(rule?.recall)} detail="attack flows caught" />
        <Kpi
          label="False alerts / h"
          value={fixed(report.false_alerts_per_hour, 1)}
          detail="merged like the live correlator"
        />
        <Kpi
          label="Flow FPR"
          value={percent(rule?.false_positive_rate, 2)}
          detail="benign flows flagged"
        />
        <Kpi label="PR-AUC" value={fixed(supervised?.pr_auc)} detail="classifier" />
        <Kpi
          label="Macro-F1"
          value={fixed(report.multiclass?.macro_f1_known_families)}
          detail={
            known.length === 1 && known[0]
              ? `only ${known[0]} in both splits`
              : "families seen in training"
          }
        />
      </section>

      <p className="text-meta text-ink-muted">
        {report.training?.split ?? "Held-out test split"} · {count(report.rows ?? 0)} test flows
        {report.benign_hours ? ` · ${report.benign_hours.toFixed(1)} h of benign traffic` : ""}.
        Families marked “unseen” were never in the training data, so catching them is the novelty
        detector’s job.
      </p>

      <div className="grid gap-4 xl:grid-cols-2">
        <Panel title="Per attack family" bodyClassName="overflow-x-auto">
          {families.length === 0 ? (
            <EmptyState title="No per-family results in this report" />
          ) : (
            <table className="w-full text-dense">
              <thead className="bg-surface-sunken text-label text-ink-subtle uppercase">
                <tr>
                  <th className="px-3 py-2 text-left font-medium">Family</th>
                  <th className="px-3 py-2 text-left font-medium">Training</th>
                  <th className="px-3 py-2 text-right font-medium">Test flows</th>
                  <th className="px-3 py-2 text-right font-medium">Alerted</th>
                </tr>
              </thead>
              <tbody>
                {families.map(([name, f]) => (
                  <tr key={name} className="border-t border-line">
                    <td className="px-3 py-1.5">{humanize(name)}</td>
                    <td className="px-3 py-1.5">
                      {name === "benign" ? (
                        "—"
                      ) : f.seen_in_training ? (
                        <Tag mono={false}>seen</Tag>
                      ) : (
                        <Tag mono={false}>unseen</Tag>
                      )}
                    </td>
                    <td className="px-3 py-1.5 text-right tabular-nums">
                      {f.rows.toLocaleString()}
                    </td>
                    <td
                      className={cx(
                        "px-3 py-1.5 text-right tabular-nums",
                        name === "benign" && f.alert_rate > 0.01 && "text-sev-high",
                      )}
                    >
                      {percent(f.alert_rate)}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </Panel>

        <Panel title="Threshold" bodyClassName="p-3 flex flex-col gap-3">
          {report.threshold_sweep_supervised?.length ? (
            <ThresholdCurve
              points={report.threshold_sweep_supervised}
              operating={supervised?.threshold ?? 0.5}
            />
          ) : (
            <EmptyState title="No threshold sweep in this report" />
          )}
          {report.validation && (
            <p className="text-meta text-ink-muted">
              Novelty threshold {fixed(report.validation.threshold, 4)} chosen on validation data
              for a budget of {report.validation.budget_alerts_per_hour ?? "—"} alerts/h
              (validation: {fixed(report.validation.validation_false_alerts_per_hour, 2)} false
              alerts/h). Novelty alone: precision {percent(novelty?.precision)}, recall{" "}
              {percent(novelty?.recall)}.
            </p>
          )}
        </Panel>
      </div>

      {matrix && (
        <Panel title="Confusion matrix (row-normalised)" bodyClassName="p-3">
          <ConfusionHeatmap labels={matrix.labels} matrix={matrix.matrix} />
        </Panel>
      )}

      {perClass.length > 0 && (
        <Panel title="Per class" bodyClassName="overflow-x-auto">
          <table className="w-full text-dense">
            <thead className="bg-surface-sunken text-label text-ink-subtle uppercase">
              <tr>
                <th className="px-3 py-2 text-left font-medium">Class</th>
                <th className="px-3 py-2 text-right font-medium">Precision</th>
                <th className="px-3 py-2 text-right font-medium">Recall</th>
                <th className="px-3 py-2 text-right font-medium">F1</th>
                <th className="px-3 py-2 text-right font-medium">Support</th>
              </tr>
            </thead>
            <tbody>
              {perClass.map(([name, m]) => (
                <tr key={name} className="border-t border-line">
                  <td className="px-3 py-1.5">{humanize(name)}</td>
                  <td className="px-3 py-1.5 text-right tabular-nums">{percent(m.precision)}</td>
                  <td className="px-3 py-1.5 text-right tabular-nums">{percent(m.recall)}</td>
                  <td className="px-3 py-1.5 text-right tabular-nums">{fixed(m["f1-score"])}</td>
                  <td className="px-3 py-1.5 text-right tabular-nums">
                    {m.support.toLocaleString()}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </Panel>
      )}

      {report.training && (
        <Panel title="Training" bodyClassName="p-4 flex flex-col gap-4">
          <Facts
            columns={3}
            items={[
              ["Dataset", report.training.dataset ?? "—"],
              ["Split", report.training.split ?? "—"],
              ["Feature set", report.training.feature_set ?? "—"],
              [
                "Rows (fit / validation / test)",
                report.training.rows
                  ? `${count(report.training.rows.fit ?? 0)} / ${count(report.training.rows.validation ?? 0)} / ${count(report.training.rows.test ?? 0)}`
                  : "—",
              ],
              ["Best iteration", report.training.best_iteration ?? "—"],
              ["Features", report.training.features?.length ?? "—"],
            ]}
          />
          {report.training.features && (
            <div className="flex flex-wrap gap-1">
              {report.training.features.map((f) => (
                <Tag key={f}>{f}</Tag>
              ))}
            </div>
          )}
        </Panel>
      )}
    </>
  );
}
