// UI suite for the single-file demonstrator. Opens demonstrator/index.html straight from disk, no server needed.
import { defineConfig, devices } from '@playwright/test';

export default defineConfig({
  testDir: 'demonstrator/test',
  testMatch: '*.spec.mjs',
  fullyParallel: true,
  forbidOnly: !!process.env.CI,
  retries: process.env.CI ? 1 : 0,
  reporter: process.env.CI ? [['github'], ['html', { open: 'never' }]] : [['list']],
  timeout: 60_000,
  use: {
    ...devices['Desktop Chrome'],
    trace: 'on-first-retry',
    screenshot: 'only-on-failure',
  },
});
