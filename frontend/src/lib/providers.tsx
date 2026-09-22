"use client";

import { MutationCache, QueryCache, QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { useRouter } from "next/navigation";
import { useState, type ReactNode } from "react";
import { RouterProvider } from "react-aria-components";

import { ToastProvider } from "@/components/Toast";
import { ApiError } from "@/lib/api/client";
import { AuthProvider } from "@/lib/auth";

function makeClient(): QueryClient {
  const client: QueryClient = new QueryClient({
    defaultOptions: {
      queries: {
        staleTime: 10_000,
        refetchOnWindowFocus: false,
        // Don't retry what won't change: auth failures, missing records, bad input.
        retry: (failures, error) =>
          !(error instanceof ApiError && error.status >= 400 && error.status < 500) && failures < 2,
      },
    },
    // A 401 anywhere means the session ended: refresh the auth state, which redirects to login.
    queryCache: new QueryCache({ onError: (error) => signedOut(error) }),
    mutationCache: new MutationCache({ onError: (error) => signedOut(error) }),
  });
  function signedOut(error: unknown) {
    if (error instanceof ApiError && error.status === 401) {
      void client.invalidateQueries({ queryKey: ["auth", "status"] });
    }
  }
  return client;
}

export function Providers({ children }: { children: ReactNode }) {
  const [queryClient] = useState(makeClient);
  const router = useRouter();
  return (
    // React Aria links (menu items, palette actions) navigate through the Next router.
    <RouterProvider navigate={(href) => router.push(href)}>
      <QueryClientProvider client={queryClient}>
        <ToastProvider>
          <AuthProvider>{children}</AuthProvider>
        </ToastProvider>
      </QueryClientProvider>
    </RouterProvider>
  );
}
