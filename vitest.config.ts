import { defineConfig } from "vitest/config";

// Postgres roles (anon, authenticated, service_role) are cluster-wide, so test files that
// each create their own database still race on CREATE ROLE when run in parallel.
export default defineConfig({ test: { fileParallelism: false } });
