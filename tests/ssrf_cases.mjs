import {
  normalizeDomain,
  validateBackendUrl,
  validateDisableAllowed,
  validateDomain,
  validateSlugUpdate,
} from "../dashboard/lib/apps.ts";

const rejectedUrls = [
  "http://2130706433",
  "http://0x7f000001",
  "http://0177.0.0.1",
  "http://0.0.0.0",
  "http://[::1]",
  "http://[::ffff:127.0.0.1]",
  "http://[::ffff:7f00:1]",
  "http://[fe80::1]",
  "http://[fc00::1]",
  "http://[fd00::1]",
  "http://[ff02::1]",
  "http://[2001:db8::1]",
  "http://169.254.169.254",
  "http://metadata.google.internal",
  "http://10.0.0.1",
  "http://172.16.0.1",
  "http://192.168.1.1",
  "http://100.64.0.1",
  "http://DATABASE:5432",
  "http://DATABASE.:5432",
  "http://database:5432",
  "http://127.1",
  "http://127.0.0.1.",
  "http://0",
  "http://0x7f.1",
];

const allowedUrls = [
  "http://maderera-app:3000",
  "http://pyme-php-backend:80",
  "https://example.com",
  "http://fcm.example.com",
  "http://ffmpeg.example.com",
];

const domainCases = [
  { input: "EXAMPLE.COM.", expected: "example.com" },
  { input: "database.", expectedError: true },
  { input: "localhost.", expectedError: true },
  { input: "fcm.example.com", expected: "fcm.example.com" },
  { input: "ffmpeg.example.com", expected: "ffmpeg.example.com" },
];

const slugCases = [
  { current: "default", next: undefined, expectedOk: true },
  { current: "default", next: "default", expectedOk: true },
  { current: "default", next: "other", expectedOk: false },
];

const disableCases = [
  { current: true, count: 2, expectedOk: true },
  { current: true, count: 1, expectedOk: false },
  { current: false, count: 1, expectedOk: true },
];

console.log(
  JSON.stringify({
    rejectedUrls: rejectedUrls.map((url) => ({ url, result: validateBackendUrl(url) })),
    allowedUrls: allowedUrls.map((url) => ({ url, result: validateBackendUrl(url) })),
    domainCases: domainCases.map((item) => ({
      ...item,
      normalized: normalizeDomain(item.input),
      result: validateDomain(item.input),
    })),
    slugCases: slugCases.map((item) => ({
      current: item.current,
      next: item.next ?? null,
      expectedOk: item.expectedOk,
      result: validateSlugUpdate(item.current, item.next),
    })),
    disableCases: disableCases.map((item) => ({
      ...item,
      result: validateDisableAllowed(item.current, item.count),
    })),
  })
);
