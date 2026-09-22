"use client";

import { useRouter } from "next/navigation";
import { useEffect, useState } from "react";
import { Form } from "react-aria-components";

import { Button } from "@/components/Button";
import { TextField } from "@/components/Field";
import { FormError } from "@/components/States";
import { useAuth } from "@/lib/auth";

import { AuthFrame } from "../AuthFrame";

export default function LoginPage() {
  const { status, login } = useAuth();
  const router = useRouter();
  const [username, setUsername] = useState("admin");
  const [password, setPassword] = useState("");
  const [error, setError] = useState<unknown>(null);
  const [busy, setBusy] = useState(false);

  useEffect(() => {
    if (status?.setup_required) router.replace("/setup/");
    else if (status?.authenticated) router.replace("/");
  }, [status, router]);

  return (
    <AuthFrame>
      <h1 className="text-page font-semibold">Sign in</h1>
      <p className="mt-1 mb-6 text-ink-muted">
        This console controls packet capture on this machine.
      </p>
      <Form
        className="flex flex-col gap-4"
        onSubmit={(event) => {
          event.preventDefault();
          setBusy(true);
          setError(null);
          login(username, password)
            .then(() => router.replace("/"))
            .catch(setError)
            .finally(() => setBusy(false));
        }}
      >
        <TextField
          label="Username"
          value={username}
          onChange={setUsername}
          isRequired
          autoComplete="username"
          autoFocus
        />
        <TextField
          label="Password"
          type="password"
          value={password}
          onChange={setPassword}
          isRequired
          autoComplete="current-password"
        />
        <FormError error={error} />
        <Button type="submit" variant="primary" loading={busy}>
          Sign in
        </Button>
      </Form>
    </AuthFrame>
  );
}
