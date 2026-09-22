import path from "node:path";

export const PASSWORD = "correct horse battery staple";

/** Labelled captures shared with the backend tests (see backend/tests/fixtures/pcaps). */
export const fixture = (name: string) =>
  path.resolve(__dirname, "../../../backend/tests/fixtures/pcaps", name);

/** Every signed-in page, for the accessibility sweep. */
export const APP_ROUTES = [
  "/",
  "/alerts/",
  "/flows/",
  "/hosts/",
  "/sessions/",
  "/model/",
  "/jobs/",
  "/system/",
  "/settings/",
];
