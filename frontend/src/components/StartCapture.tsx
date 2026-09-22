"use client";

import { PlayIcon } from "@phosphor-icons/react";
import { useState } from "react";

import { useInterfaces, useSensorControl } from "@/lib/queries";

import { Button } from "./Button";
import { Select, type Option } from "./Field";
import { DialogBox } from "./Overlays";
import { FormError } from "./States";
import { useToast } from "./Toast";

export function interfaceOptions(
  interfaces: { name: string; label: string; ipv4: string[]; loopback: boolean }[] | undefined,
): Option[] {
  return (interfaces ?? []).map((i) => ({
    id: i.name,
    label: i.label || i.name,
    description:
      [i.ipv4.join(", "), i.loopback ? "loopback" : ""].filter(Boolean).join(" · ") || undefined,
  }));
}

/** Pick an interface and start live capture. */
export function StartCaptureDialog({ isOpen, onClose }: { isOpen: boolean; onClose: () => void }) {
  const interfaces = useInterfaces(isOpen);
  const { start } = useSensorControl();
  const notify = useToast();
  const [chosen, setChosen] = useState<string | null>(null);
  const [backend, setBackend] = useState<"auto" | "scapy" | "nfstream">("auto");
  const options = interfaceOptions(interfaces.data);
  const selected = chosen ?? options[0]?.id ?? null;

  return (
    <DialogBox isOpen={isOpen} onClose={onClose} title="Start capture">
      <Select
        label="Interface"
        options={options}
        value={selected}
        onChange={setChosen}
        isDisabled={interfaces.isPending}
        placeholder={interfaces.isPending ? "Loading interfaces…" : "No interfaces found"}
        description="Capturing needs Npcap on Windows or CAP_NET_RAW on Linux. System → Capabilities shows what's missing."
      />
      <Select
        label="Capture backend"
        options={[
          {
            id: "auto",
            label: "Automatic",
            description: "NFStream on Linux when installed, otherwise Scapy",
          },
          { id: "scapy", label: "Scapy" },
          { id: "nfstream", label: "NFStream (Linux)" },
        ]}
        value={backend}
        onChange={(v) => setBackend(v as typeof backend)}
      />
      <FormError error={start.error ?? interfaces.error} />
      <div className="flex justify-end gap-2">
        <Button variant="ghost" onPress={onClose}>
          Cancel
        </Button>
        <Button
          variant="primary"
          icon={<PlayIcon size={14} weight="fill" aria-hidden />}
          isDisabled={!selected}
          loading={start.isPending}
          onPress={() =>
            selected &&
            start.mutate(
              { interface: selected, backend },
              {
                onSuccess: () => {
                  notify(`Capturing on ${selected}.`, { tone: "ok" });
                  onClose();
                },
              },
            )
          }
        >
          Start
        </Button>
      </div>
    </DialogBox>
  );
}
