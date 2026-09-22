"use client";

import {
  BriefcaseIcon,
  FileArrowUpIcon,
  PlayIcon,
  UploadSimpleIcon,
  XCircleIcon,
} from "@phosphor-icons/react";
import { useState } from "react";
import { DropZone, FileTrigger, Form } from "react-aria-components";

import { RelativeTime } from "@/components/AlertBits";
import { Dot, Tag } from "@/components/Badges";
import { Button, TextLink } from "@/components/Button";
import { cx } from "@/components/cx";
import { DataTable, columnHelper } from "@/components/DataTable";
import { NumberField, Select, Switch } from "@/components/Field";
import { LogTail } from "@/components/LogTail";
import { Drawer } from "@/components/Overlays";
import { Facts, PageHeader, Panel } from "@/components/Panel";
import { EmptyState, FormError, QueryView, SkeletonRows } from "@/components/States";
import { useToast } from "@/components/Toast";
import type { Schemas } from "@/lib/api/client";
import { absoluteTime, bytes, duration, humanize } from "@/lib/format";
import {
  useCancelJob,
  useJobs,
  useLogs,
  useStartJob,
  useUploadPcap,
  useUploads,
  type Job,
} from "@/lib/queries";

type Upload = Schemas["UploadOut"];
type Dataset = Schemas["TrainJob"]["dataset"];

const DATASETS = [
  { id: "cicids2017", label: "CIC-IDS2017", description: "Corrected release; day or random split" },
  { id: "unsw-nb15", label: "UNSW-NB15", description: "Official train/test split" },
];

function jobTone(status: string): "ok" | "warn" | "off" | "bad" {
  if (status === "running" || status === "queued") return "warn";
  if (status === "done") return "ok";
  if (status === "failed") return "bad";
  return "off";
}

function jobLabel(job: Job, uploads?: Upload[]): string {
  const p = job.params as Record<string, unknown>;
  if (job.kind === "replay") {
    const name = uploads?.find((u) => u.id === p.upload_id)?.filename;
    return `Replay ${name ?? String(p.upload_id ?? "")}`;
  }
  if (job.kind === "train")
    return `Train ${String(p.dataset ?? "")} · ${String(p.protocol ?? "")} · ${String(p.features ?? "")}`;
  if (job.kind === "prepare") return `Prepare ${String(p.dataset ?? "")}`;
  if (job.kind === "sensor") return `Live capture ${String(p.interface ?? "")}`;
  if (job.kind === "report") return `Report for session ${String(p.session_id ?? "")}`;
  return humanize(job.kind);
}

/** Job name, with the uploaded file's name for replays (uploads are cached, so this is cheap). */
function JobName({ job }: { job: Job }) {
  const uploads = useUploads();
  return <>{jobLabel(job, uploads.data)}</>;
}

const col = columnHelper<Job>();
const columns = col.columns([
  col.accessor("created_at", {
    header: "Started",
    cell: (c) => <RelativeTime epoch={c.getValue()} />,
  }),
  col.display({
    id: "what",
    header: "Job",
    cell: (c) => (
      <span className="font-medium">
        <JobName job={c.row.original} />
      </span>
    ),
  }),
  col.accessor("status", {
    header: "Status",
    cell: (c) => (
      <span className="inline-flex items-center gap-1.5">
        <Dot tone={jobTone(c.getValue())} pulse={c.getValue() === "running"} />
        {humanize(c.getValue())}
      </span>
    ),
  }),
  col.display({
    id: "took",
    header: "Took",
    cell: (c) => {
      const j = c.row.original;
      return (
        <span className="tabular-nums">
          {j.started_at && j.finished_at ? duration(j.finished_at - j.started_at) : "—"}
        </span>
      );
    },
  }),
  col.accessor("created_by", {
    header: "By",
    cell: (c) => <span className="text-ink-muted">{c.getValue()}</span>,
  }),
]);

export default function JobsPage() {
  const jobs = useJobs();
  const [selected, setSelected] = useState<string | null>(null);
  const job = jobs.data?.find((j) => j.id === selected) ?? null;
  return (
    <>
      <PageHeader
        title="Jobs"
        description="Replay packet captures, prepare datasets and train models. Each job runs as its own process."
      />
      <div className="grid gap-4 xl:grid-cols-[minmax(0,1.1fr)_minmax(0,1fr)]">
        <Uploads />
        <TrainForm />
      </div>
      <Panel title="History">
        <QueryView query={jobs}>
          {(list) => (
            <DataTable
              label="Jobs"
              data={list}
              columns={columns}
              template="110px minmax(240px,2fr) 120px 96px minmax(80px,0.6fr)"
              rowKey={(j) => j.id}
              selectedKey={selected}
              onOpen={(j) => setSelected(j.id)}
              height="420px"
              empty={<EmptyState icon={BriefcaseIcon} title="No jobs yet" />}
            />
          )}
        </QueryView>
      </Panel>
      <JobDrawer job={job} onClose={() => setSelected(null)} />
    </>
  );
}

function Uploads() {
  const uploads = useUploads();
  const upload = useUploadPcap();
  const notify = useToast();
  const [useModel, setUseModel] = useState(true);
  const start = useStartJob();

  const send = (files: File[]) => {
    const file = files[0];
    if (!file) return;
    upload.mutate(file, { onSuccess: (u) => notify(`Uploaded ${u.filename}.`, { tone: "ok" }) });
  };

  const replay = (u: Upload) =>
    start.mutate(
      { kind: "replay", upload_id: u.id, use_model: useModel },
      {
        onSuccess: () =>
          notify(`Replaying ${u.filename}. Results appear under Sessions and Alerts.`, {
            tone: "ok",
          }),
      },
    );

  return (
    <Panel title="Replay a capture" bodyClassName="flex flex-col gap-3 p-4">
      <DropZone
        aria-label="Drop a .pcap or .pcapng file"
        onDrop={async (event) => {
          const items = event.items.filter((item) => item.kind === "file");
          const files = await Promise.all(
            items.map((item) => (item.kind === "file" ? item.getFile() : null)),
          );
          send(files.filter((f): f is File => f !== null));
        }}
        className={cx(
          "flex flex-col items-center gap-2 rounded-[var(--radius-panel)] border border-dashed border-line-strong px-4 py-6 text-center",
          "data-[drop-target]:border-accent data-[drop-target]:bg-accent-wash data-[focus-visible]:outline-2 data-[focus-visible]:outline-accent",
        )}
      >
        <FileArrowUpIcon size={24} aria-hidden className="text-ink-subtle" />
        <p className="text-ink-muted">Drop a .pcap or .pcapng here, or</p>
        <FileTrigger
          acceptedFileTypes={[".pcap", ".pcapng", ".cap"]}
          onSelect={(list) => list && send([...list])}
        >
          <Button
            size="dense"
            loading={upload.isPending}
            icon={<UploadSimpleIcon size={14} aria-hidden />}
          >
            Choose file
          </Button>
        </FileTrigger>
        <p className="text-meta text-ink-subtle">
          Files are checked by content, stored by id, and never executed.
        </p>
      </DropZone>
      <FormError error={upload.error ?? start.error} />
      <Switch isSelected={useModel} onChange={setUseModel}>
        Use the active model while replaying
      </Switch>
      <QueryView
        query={uploads}
        loading={<SkeletonRows rows={2} />}
        empty={(list) =>
          list.length === 0 ? <p className="text-meta text-ink-subtle">No uploads yet.</p> : null
        }
      >
        {(list) => (
          <ul className="flex flex-col divide-y divide-line rounded-[var(--radius-control)] border border-line">
            {list.slice(0, 8).map((u) => (
              <li key={u.id} className="flex items-center gap-3 px-3 py-2">
                <div className="flex min-w-0 flex-1 flex-col">
                  <span className="truncate font-medium">{u.filename}</span>
                  <span className="text-meta text-ink-subtle">
                    {bytes(u.size)} · {u.format} · <RelativeTime epoch={u.created_at} />
                  </span>
                </div>
                <Button
                  size="dense"
                  icon={<PlayIcon size={12} weight="fill" aria-hidden />}
                  isDisabled={start.isPending}
                  onPress={() => replay(u)}
                >
                  Replay
                </Button>
              </li>
            ))}
          </ul>
        )}
      </QueryView>
    </Panel>
  );
}

function TrainForm() {
  const start = useStartJob();
  const notify = useToast();
  const [dataset, setDataset] = useState<Dataset>("cicids2017");
  const [protocol, setProtocol] = useState<"day" | "random" | "official">("day");
  const [features, setFeatures] = useState<"full" | "shared">("full");
  const [sample, setSample] = useState(100);

  const protocols =
    dataset === "unsw-nb15"
      ? [{ id: "official", label: "Official train/test", description: "The dataset's own split" }]
      : [
          {
            id: "day",
            label: "By day",
            description: "Train Mon–Wed, test Thu–Fri: attacks in test are unseen",
          },
          {
            id: "random",
            label: "Random 80/20",
            description: "Optimistic; every family seen in training",
          },
        ];
  const chosenProtocol = protocols.some((p) => p.id === protocol)
    ? protocol
    : (protocols[0]!.id as typeof protocol);

  return (
    <Panel title="Train a model" bodyClassName="p-4">
      <Form
        className="flex flex-col gap-3"
        onSubmit={(event) => {
          event.preventDefault();
          start.mutate(
            {
              kind: "train",
              dataset,
              protocol: chosenProtocol,
              features,
              sample_frac: sample >= 100 ? null : sample / 100,
            },
            {
              onSuccess: () =>
                notify("Training started. It shows up under Model when done.", { tone: "ok" }),
            },
          );
        }}
      >
        <div className="grid gap-3 sm:grid-cols-2">
          <Select
            label="Dataset"
            options={DATASETS}
            value={dataset}
            onChange={(v) => setDataset(v as Dataset)}
          />
          <Select
            label="Split"
            options={protocols}
            value={chosenProtocol}
            onChange={(v) => setProtocol(v as typeof protocol)}
          />
          <Select
            label="Features"
            options={[
              { id: "full", label: "Full (46)", description: "Everything features_v1 computes" },
              {
                id: "shared",
                label: "Shared (14)",
                description: "Only features both datasets have; for cross-dataset tests",
              },
            ]}
            value={features}
            onChange={(v) => setFeatures(v as typeof features)}
          />
          <NumberField
            label="Sample"
            unit="% of rows"
            minValue={1}
            maxValue={100}
            value={sample}
            onChange={(v) => setSample(Number.isNaN(v) ? 100 : v)}
          />
        </div>
        <p className="text-meta text-ink-subtle">
          Download the dataset first (see <span className="font-mono">backend/data/README.md</span>
          ), then prepare it once. A full CIC-IDS2017 run takes several minutes.
        </p>
        <FormError error={start.error} />
        <div className="flex flex-wrap gap-2">
          <Button type="submit" variant="primary" loading={start.isPending}>
            Start training
          </Button>
          <Button
            isDisabled={start.isPending}
            onPress={() =>
              start.mutate(
                { kind: "prepare", dataset },
                { onSuccess: () => notify("Preparing the dataset.", { tone: "ok" }) },
              )
            }
          >
            Prepare dataset
          </Button>
        </div>
      </Form>
    </Panel>
  );
}

function JobDrawer({ job, onClose }: { job: Job | null; onClose: () => void }) {
  const cancel = useCancelJob();
  const notify = useToast();
  const running = job?.status === "running" || job?.status === "queued";
  return (
    <Drawer
      isOpen={job !== null}
      onClose={onClose}
      title={job ? <JobName job={job} /> : "Job"}
      subtitle={job && <span className="font-mono">{job.id}</span>}
      footer={
        running &&
        job && (
          <Button
            size="dense"
            variant="danger"
            loading={cancel.isPending}
            icon={<XCircleIcon size={14} aria-hidden />}
            onPress={() => cancel.mutate(job.id, { onSuccess: () => notify("Stopping the job…") })}
          >
            Cancel job
          </Button>
        )
      }
    >
      {job && <JobBody job={job} />}
    </Drawer>
  );
}

function JobBody({ job }: { job: Job }) {
  const logs = useLogs(`job:${job.id}`, 400);
  const result = Object.entries(job.result ?? {});
  return (
    <div className="flex flex-col gap-5">
      <Facts
        items={[
          ["Status", humanize(job.status)],
          ["Exit code", job.exit_code ?? "—"],
          ["Created", absoluteTime(job.created_at)],
          ["Finished", job.finished_at ? absoluteTime(job.finished_at) : "—"],
        ]}
      />
      <section className="flex flex-col gap-2">
        <h3 className="text-label font-medium text-ink-subtle uppercase">Parameters</h3>
        <div className="flex flex-wrap gap-1">
          {Object.entries(job.params ?? {}).map(([k, v]) => (
            <Tag key={k}>
              {k}={String(v)}
            </Tag>
          ))}
        </div>
      </section>
      {result.length > 0 && (
        <section className="flex flex-col gap-2">
          <h3 className="text-label font-medium text-ink-subtle uppercase">Result</h3>
          <pre className="max-h-60 overflow-auto rounded-[var(--radius-control)] bg-surface-sunken p-3 font-mono text-meta">
            {JSON.stringify(job.result, null, 2)}
          </pre>
          {typeof job.result.session === "string" && (
            <p className="flex gap-3 text-meta">
              <TextLink href={`/alerts/?session=${job.result.session}`}>
                Alerts from this replay
              </TextLink>
              <TextLink href={`/flows/?session=${job.result.session}`}>Flows</TextLink>
            </p>
          )}
        </section>
      )}
      <section className="flex flex-col gap-2">
        <h3 className="text-label font-medium text-ink-subtle uppercase">Log</h3>
        {logs.error ? (
          <p className="text-meta text-ink-subtle">No log for this job.</p>
        ) : (
          <LogTail lines={logs.data?.lines ?? []} />
        )}
      </section>
    </div>
  );
}
