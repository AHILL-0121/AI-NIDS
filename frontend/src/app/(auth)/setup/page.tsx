"use client";

import { ArrowRightIcon, CheckIcon } from "@phosphor-icons/react";
import { useRouter } from "next/navigation";
import { useEffect, useState } from "react";
import { Form } from "react-aria-components";

import { HealthIcon } from "@/components/Badges";
import { Button } from "@/components/Button";
import { cx } from "@/components/cx";
import { Select, TextField } from "@/components/Field";
import { interfaceOptions } from "@/components/StartCapture";
import { FormError, QueryView } from "@/components/States";
import { useToast } from "@/components/Toast";
import { useAuth } from "@/lib/auth";
import { absoluteTime } from "@/lib/format";
import {
  useCapabilities,
  useInterfaces,
  useModelActivation,
  useModels,
  useSensorControl,
} from "@/lib/queries";

import { AuthFrame } from "../AuthFrame";

const STEPS = ["Admin account", "Capture check", "Interface", "Detection model"] as const;

export default function SetupPage() {
  const { status } = useAuth();
  const router = useRouter();
  const [step, setStep] = useState(0);

  // Reloading after the account exists resumes at step 2; a signed-out visitor goes to login.
  const current = status?.authenticated && step === 0 ? 1 : step;
  useEffect(() => {
    if (status && !status.setup_required && !status.authenticated) router.replace("/login/");
  }, [status, router]);

  const next = () => setStep(current + 1);
  const finish = () => router.replace("/");

  return (
    <AuthFrame wide>
      <p className="text-label font-medium text-ink-subtle uppercase">First-run setup</p>
      <h1 className="mt-1 text-page font-semibold">Set up this sensor</h1>
      <ol className="mt-5 mb-6 grid grid-cols-4 gap-2" aria-label="Setup progress">
        {STEPS.map((name, i) => (
          <li
            key={name}
            aria-current={i === current ? "step" : undefined}
            className="flex flex-col gap-1.5"
          >
            <span
              className={cx("h-1 rounded-full", i <= current ? "bg-accent" : "bg-surface-sunken")}
            />
            <span
              className={cx(
                "text-meta",
                i === current ? "font-medium text-ink" : "text-ink-subtle",
              )}
            >
              {i < current && (
                <CheckIcon size={11} aria-hidden className="mr-1 inline text-accent" />
              )}
              {name}
            </span>
          </li>
        ))}
      </ol>
      <div className="rounded-[var(--radius-panel)] border border-line bg-surface p-5">
        {current === 0 && <AccountStep onDone={next} />}
        {current === 1 && <CapabilityStep onDone={next} />}
        {current === 2 && <InterfaceStep onDone={next} />}
        {current === 3 && <ModelStep onDone={finish} />}
      </div>
    </AuthFrame>
  );
}

function AccountStep({ onDone }: { onDone: () => void }) {
  const { setup } = useAuth();
  const [username, setUsername] = useState("admin");
  const [password, setPassword] = useState("");
  const [confirm, setConfirm] = useState("");
  const [error, setError] = useState<unknown>(null);
  const [busy, setBusy] = useState(false);
  const mismatch = confirm.length > 0 && confirm !== password;

  return (
    <Form
      className="flex flex-col gap-4"
      onSubmit={(event) => {
        event.preventDefault();
        if (mismatch) return;
        setBusy(true);
        setError(null);
        setup(username, password)
          .then(onDone)
          .catch(setError)
          .finally(() => setBusy(false));
      }}
    >
      <p className="text-ink-muted">
        One administrator account protects this console. The password is stored as an argon2id hash
        on this machine.
      </p>
      <TextField
        label="Username"
        value={username}
        onChange={setUsername}
        isRequired
        autoComplete="username"
      />
      <TextField
        label="Password"
        type="password"
        value={password}
        onChange={setPassword}
        isRequired
        minLength={12}
        autoComplete="new-password"
        description="At least 12 characters. A passphrase of a few unrelated words works well."
      />
      <TextField
        label="Confirm password"
        type="password"
        value={confirm}
        onChange={setConfirm}
        isRequired
        isInvalid={mismatch}
        errorMessage="The passwords don't match."
        autoComplete="new-password"
      />
      <FormError error={error} />
      <div className="flex justify-end">
        <Button
          type="submit"
          variant="primary"
          loading={busy}
          icon={<ArrowRightIcon size={14} aria-hidden />}
        >
          Create account
        </Button>
      </div>
    </Form>
  );
}

function CapabilityStep({ onDone }: { onDone: () => void }) {
  const capabilities = useCapabilities();
  return (
    <div className="flex flex-col gap-4">
      <p className="text-ink-muted">
        Live capture needs raw packet access. Replaying .pcap files works without it.
      </p>
      <QueryView query={capabilities}>
        {(report) => (
          <ul className="flex flex-col divide-y divide-line rounded-[var(--radius-control)] border border-line">
            {report.checks.map((check) => (
              <li key={check.name} className="flex gap-3 px-3 py-2.5">
                <HealthIcon health={check.status} />
                <div className="flex min-w-0 flex-col gap-0.5">
                  <span className="font-medium">{check.name}</span>
                  <span className="text-meta text-ink-muted">{check.detail}</span>
                  {check.fix && check.status !== "ok" && (
                    <span className="text-meta text-ink">
                      <span className="font-medium">Fix: </span>
                      {check.fix}
                    </span>
                  )}
                </div>
              </li>
            ))}
          </ul>
        )}
      </QueryView>
      <div className="flex justify-end gap-2">
        <Button
          variant="ghost"
          onPress={() => void capabilities.refetch()}
          loading={capabilities.isFetching}
        >
          Check again
        </Button>
        <Button variant="primary" onPress={onDone} icon={<ArrowRightIcon size={14} aria-hidden />}>
          {capabilities.data?.ok ? "Continue" : "Continue anyway"}
        </Button>
      </div>
    </div>
  );
}

function InterfaceStep({ onDone }: { onDone: () => void }) {
  const interfaces = useInterfaces();
  const { start } = useSensorControl();
  const notify = useToast();
  const options = interfaceOptions(interfaces.data);
  const [chosen, setChosen] = useState<string | null>(null);
  const selected = chosen ?? options[0]?.id ?? null;

  return (
    <div className="flex flex-col gap-4">
      <p className="text-ink-muted">
        Choose the network interface to watch. You can start capturing now or later from the top
        bar.
      </p>
      <Select
        label="Interface"
        options={options}
        value={selected}
        onChange={setChosen}
        isDisabled={interfaces.isPending}
        placeholder={interfaces.isPending ? "Loading interfaces…" : "No interfaces found"}
      />
      <FormError error={interfaces.error ?? start.error} />
      <div className="flex justify-end gap-2">
        <Button variant="ghost" onPress={onDone}>
          Skip for now
        </Button>
        <Button
          variant="primary"
          isDisabled={!selected}
          loading={start.isPending}
          onPress={() =>
            selected &&
            start.mutate(
              { interface: selected, backend: "auto" },
              {
                onSuccess: () => {
                  notify(`Capturing on ${selected}.`, { tone: "ok" });
                  onDone();
                },
              },
            )
          }
        >
          Start capture
        </Button>
      </div>
    </div>
  );
}

function ModelStep({ onDone }: { onDone: () => void }) {
  const models = useModels();
  const { activate } = useModelActivation();
  const [chosen, setChosen] = useState<string | null>(null);
  const active = models.data?.find((m) => m.active)?.version ?? null;
  const selected = chosen ?? active ?? models.data?.[0]?.version ?? null;

  return (
    <div className="flex flex-col gap-4">
      <p className="text-ink-muted">
        The rule-based detectors (scans, sweeps, floods, protocol allow-list) always run. A trained
        model adds classification of known attack families and novelty detection.
      </p>
      <QueryView
        query={models}
        empty={(list) =>
          list.length === 0 ? (
            <p className="rounded-[var(--radius-control)] bg-surface-sunken px-3 py-2.5 text-meta text-ink-muted">
              No trained models yet. Train one later from <span className="font-medium">Jobs</span>,
              or with <code className="font-mono">nids train</code>.
            </p>
          ) : null
        }
      >
        {(list) => (
          <Select
            label="Model"
            value={selected}
            onChange={setChosen}
            options={list.map((m) => ({
              id: m.version,
              label: m.version,
              description: [
                m.dataset,
                m.protocol && `${m.protocol} split`,
                absoluteTime(m.created_at),
                m.active && "active",
              ]
                .filter(Boolean)
                .join(" · "),
            }))}
          />
        )}
      </QueryView>
      <FormError error={activate.error} />
      <div className="flex justify-end gap-2">
        <Button variant="ghost" onPress={onDone}>
          Skip
        </Button>
        <Button
          variant="primary"
          isDisabled={!selected}
          loading={activate.isPending}
          onPress={() => selected && activate.mutate(selected, { onSuccess: onDone })}
        >
          Activate and finish
        </Button>
      </div>
    </div>
  );
}
