import * as core from "@actions/core";
import { setLogger } from "./logger";
import { runAPIMode } from "./api_client";

setLogger({
  info: (msg) => core.info(msg),
  warning: (msg) => core.warning(msg),
  debug: (msg) => core.debug(msg),
});

async function main(): Promise<void> {
  const apiKey = core.getInput("api_key") || "";

  if (!apiKey) {
    throw new Error(
      "api_key is required. Get your key at https://westbayberry.com/dashboard"
    );
  }

  await runAPIMode(apiKey);
}

main().catch((err) => {
  const msg = err instanceof Error ? err.message : String(err);
  core.setFailed(`Dependency Guardian failed: ${msg}`);
});
