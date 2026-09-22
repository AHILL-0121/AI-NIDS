"use client";

import { useQuery, useQueryClient } from "@tanstack/react-query";
import { usePathname, useRouter } from "next/navigation";
import { createContext, useCallback, useContext, useEffect, type ReactNode } from "react";

import { client, setCsrfToken, unwrap, type Schemas } from "@/lib/api/client";

type AuthStatus = Schemas["AuthStatus"];

interface AuthContextValue {
  status: AuthStatus | undefined;
  loading: boolean;
  setup: (username: string, password: string) => Promise<void>;
  login: (username: string, password: string) => Promise<void>;
  logout: () => Promise<void>;
}

const AuthContext = createContext<AuthContextValue | null>(null);
const STATUS_KEY = ["auth", "status"] as const;

export function AuthProvider({ children }: { children: ReactNode }) {
  const queryClient = useQueryClient();
  const { data: status, isPending } = useQuery({
    queryKey: STATUS_KEY,
    queryFn: () => unwrap(client.GET("/api/auth/status")),
    staleTime: 60_000,
  });

  useEffect(() => {
    setCsrfToken(status?.csrf_token ?? null);
  }, [status?.csrf_token]);

  const signedIn = useCallback(
    (next: AuthStatus) => {
      setCsrfToken(next.csrf_token ?? null);
      queryClient.setQueryData(STATUS_KEY, next);
    },
    [queryClient],
  );

  const value: AuthContextValue = {
    status,
    loading: isPending,
    setup: async (username, password) =>
      signedIn(await unwrap(client.POST("/api/auth/setup", { body: { username, password } }))),
    login: async (username, password) =>
      signedIn(await unwrap(client.POST("/api/auth/login", { body: { username, password } }))),
    logout: async () => {
      await unwrap(client.POST("/api/auth/logout"));
      setCsrfToken(null);
      queryClient.clear();
      queryClient.setQueryData(STATUS_KEY, { setup_required: false, authenticated: false });
    },
  };
  return <AuthContext value={value}>{children}</AuthContext>;
}

export function useAuth(): AuthContextValue {
  const value = useContext(AuthContext);
  if (!value) throw new Error("useAuth must be used inside <AuthProvider>");
  return value;
}

/** Where the current auth state says this browser belongs, or null to stay. */
export function authRedirect(status: AuthStatus | undefined, pathname: string): string | null {
  if (!status) return null;
  if (status.setup_required) return pathname.startsWith("/setup") ? null : "/setup/";
  if (!status.authenticated) return pathname.startsWith("/login") ? null : "/login/";
  return null;
}

/** Renders children only for a signed-in admin; otherwise sends the browser to setup or login. */
export function RequireAuth({ children, fallback }: { children: ReactNode; fallback: ReactNode }) {
  const { status, loading } = useAuth();
  const pathname = usePathname();
  const router = useRouter();
  const target = authRedirect(status, pathname);

  useEffect(() => {
    if (target) router.replace(target);
  }, [target, router]);

  if (loading || target || !status?.authenticated) return <>{fallback}</>;
  return <>{children}</>;
}
