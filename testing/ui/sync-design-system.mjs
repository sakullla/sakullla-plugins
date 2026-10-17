#!/usr/bin/env node
// Sync the canonical plugin UI kit into each plugin's static UI root.
// No dependencies. Usage:
//   node testing/ui/sync-design-system.mjs            # write all copies
//   node testing/ui/sync-design-system.mjs --check    # verify all copies
//   node testing/ui/sync-design-system.mjs --plugin waf
import { mkdir, readFile, writeFile } from "node:fs/promises";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const root = resolve(dirname(fileURLToPath(import.meta.url)), "../..");
const sourceDir = join(root, "internal/ui/design-system");
const files = ["ui-kit.css", "ui-kit.js"];

const targets = {
  "accelerator-sources": "plugins/accelerator-sources/web/static",
  "cloudflare-dns": "plugins/cloudflare-dns/ui",
  "docker-app": "plugins/docker-app/assets/ui",
  "doh": "plugins/doh/static",
  "ip-policy": "plugins/ip-policy/assets/ui",
  "reverse-l4": "plugins/reverse-l4/assets/ui",
  "shadowsocks-server": "plugins/shadowsocks-server/assets/ui",
  "waf": "plugins/waf/assets/ui",
  "webdav": "plugins/webdav/static"
};

function usage() {
  console.log(`Usage: node testing/ui/sync-design-system.mjs [--check] [--plugin <id>]`);
  console.log(`Plugins: ${Object.keys(targets).join(", ")}`);
}

function parseArgs(argv) {
  let check = false;
  let plugin = "";
  for (let index = 0; index < argv.length; index += 1) {
    const arg = argv[index];
    if (arg === "--check") check = true;
    else if (arg === "--plugin") {
      plugin = argv[index + 1] || "";
      index += 1;
    } else if (arg === "-h" || arg === "--help") {
      usage();
      process.exit(0);
    } else {
      console.error(`Unknown argument: ${arg}`);
      usage();
      process.exit(2);
    }
  }
  if (plugin && !targets[plugin]) {
    console.error(`Unknown plugin: ${plugin}`);
    usage();
    process.exit(2);
  }
  return { check, plugin };
}

async function readSource(name) {
  try {
    return await readFile(join(sourceDir, name));
  } catch (error) {
    console.error(`Missing canonical source: internal/ui/design-system/${name}`);
    throw error;
  }
}

async function main() {
  const options = parseArgs(process.argv.slice(2));
  const names = options.plugin ? [options.plugin] : Object.keys(targets);
  let failures = 0;
  let writes = 0;

  for (const name of names) {
    const targetDir = join(root, targets[name]);
    for (const file of files) {
      const source = await readSource(file);
      const target = join(targetDir, file);
      if (options.check) {
        let current = null;
        try {
          current = await readFile(target);
        } catch (_error) {
          current = null;
        }
        if (!current) {
          console.error(`MISSING ${targets[name]}/${file}`);
          failures += 1;
        } else if (!current.equals(source)) {
          console.error(`DRIFT   ${targets[name]}/${file}`);
          failures += 1;
        }
      } else {
        await mkdir(targetDir, { recursive: true });
        await writeFile(target, source);
        writes += 1;
      }
    }
  }

  if (options.check) {
    if (failures) {
      console.error(`${failures} design-system cop${failures === 1 ? "y" : "ies"} missing or out of date.`);
      process.exit(1);
    }
    console.log(`Design system is in sync (${names.length} plugin${names.length === 1 ? "" : "s"}).`);
    return;
  }
  console.log(`Wrote ${writes} design-system file${writes === 1 ? "" : "s"} for ${names.length} plugin${names.length === 1 ? "" : "s"}.`);
}

main().catch((error) => {
  console.error(error?.stack || String(error));
  process.exit(1);
});
