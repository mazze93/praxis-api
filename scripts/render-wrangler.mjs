import { readFile, writeFile } from "node:fs/promises";

const required = [
  "POLICY_KV_ID",
  "POLICY_KV_PREVIEW_ID",
  "SESSION_KV_ID",
  "SESSION_KV_PREVIEW_ID",
  "QUOTA_KV_ID",
  "QUOTA_KV_PREVIEW_ID",
];

const missing = required.filter((key) => !process.env[key]);
if (missing.length) {
  console.error(`Missing required environment variables: ${missing.join(", ")}`);
  process.exit(1);
}

let source = await readFile("wrangler.jsonc", "utf8");
const replacements = {
  REPLACE_WITH_POLICY_KV_ID: process.env.POLICY_KV_ID,
  REPLACE_WITH_POLICY_KV_PREVIEW_ID: process.env.POLICY_KV_PREVIEW_ID,
  REPLACE_WITH_SESSION_KV_ID: process.env.SESSION_KV_ID,
  REPLACE_WITH_SESSION_KV_PREVIEW_ID: process.env.SESSION_KV_PREVIEW_ID,
  REPLACE_WITH_QUOTA_KV_ID: process.env.QUOTA_KV_ID,
  REPLACE_WITH_QUOTA_KV_PREVIEW_ID: process.env.QUOTA_KV_PREVIEW_ID,
};

for (const [needle, value] of Object.entries(replacements)) {
  source = source.replaceAll(needle, value);
}

if (source.includes("REPLACE_WITH_")) {
  console.error("Generated Wrangler config still contains unresolved placeholders.");
  process.exit(1);
}

await writeFile(".wrangler.generated.jsonc", source);
console.log("Rendered .wrangler.generated.jsonc");
