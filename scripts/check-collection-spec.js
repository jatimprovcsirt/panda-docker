#!/usr/bin/env node
//
// Asserts that the Postman collection and the OpenAPI document describe the
// same set of endpoints.
//
// The collection is what an agency imports and the specification is what the
// portal renders, so a divergence means the two audiences are being told
// different things. Neither tool notices on its own: a path added to the
// specification and forgotten in the collection is invisible until someone
// tries to call it.
//
// This compares the SET of endpoint-and-method pairs, not the number of
// requests. The collection deliberately holds more requests than there are
// endpoints — a second call demonstrating a malformed envelope, for instance
// — and counting them would fail for the wrong reason.
//
// No dependencies: the repository has none for Node, and adding a YAML parser
// to check one hand-written file is not worth the supply chain. The parse
// below is narrow and asserts what it found, so a structure it does not
// understand fails loudly instead of quietly reporting no mismatches.
//
// Usage: node scripts/check-collection-spec.js

"use strict";

const fs = require("fs");
const path = require("path");

const ROOT = path.join(__dirname, "..");
const SPEC = path.join(ROOT, "openapi", "panda-v1.yaml");
const COLLECTION = path.join(ROOT, "postman", "panda.postman_collection.json");

const METHODS = ["get", "post", "put", "patch", "delete", "head", "options"];

// --- the specification -------------------------------------------------------

function endpointsFromSpec(yaml) {
  const found = new Map();
  const lines = yaml.split(/\r?\n/);

  let inPaths = false;
  let currentPath = null;

  for (const line of lines) {
    if (/^paths:\s*$/.test(line)) {
      inPaths = true;
      continue;
    }
    if (!inPaths) continue;

    // A line at column zero ends the paths block.
    if (/^\S/.test(line)) {
      inPaths = false;
      continue;
    }

    // "  /v1/blind-index:" — the character class here is deliberately \S,
    // which covers the hyphen. Narrower classes are how a path goes missing
    // from both sides of a comparison while the check reports success.
    const pathMatch = line.match(/^ {2}(\/\S*):\s*$/);
    if (pathMatch) {
      currentPath = pathMatch[1];
      continue;
    }

    const methodMatch = line.match(/^ {4}([a-z]+):\s*$/);
    if (methodMatch && currentPath && METHODS.includes(methodMatch[1])) {
      found.set(`${methodMatch[1].toUpperCase()} ${currentPath}`, "specification");
    }
  }

  if (found.size === 0) {
    throw new Error(
      "no endpoints found in the OpenAPI document — the parse does not " +
        "understand the file any more, which is a failure of this check " +
        "rather than a pass"
    );
  }
  return found;
}

// --- the collection ----------------------------------------------------------

function endpointsFromCollection(collection) {
  const found = new Map();

  const walk = (items) => {
    for (const item of items || []) {
      if (Array.isArray(item.item)) {
        walk(item.item);
        continue;
      }
      if (!item.request || !item.request.url) continue;

      const url = item.request.url;
      const segments = Array.isArray(url.path) ? url.path : [];

      // A path variable would arrive as ":name". None of these endpoints
      // take one, and silently accepting it here would hide a mismatch.
      const literal = segments.filter((s) => !String(s).startsWith(":"));
      if (literal.length !== segments.length) continue;

      const key = `${String(item.request.method).toUpperCase()} /${literal.join("/")}`;
      found.set(key, item.name || "(unnamed)");
    }
  };

  walk(collection.item);

  if (found.size === 0) {
    throw new Error("no requests found in the Postman collection");
  }
  return found;
}

// --- compare -----------------------------------------------------------------

function main() {
  const spec = endpointsFromSpec(fs.readFileSync(SPEC, "utf8"));
  const collection = endpointsFromCollection(
    JSON.parse(fs.readFileSync(COLLECTION, "utf8"))
  );

  const problems = [];

  for (const [endpoint] of spec) {
    if (!collection.has(endpoint)) {
      problems.push(`in the specification but missing from the collection: ${endpoint}`);
    }
  }
  for (const [endpoint, name] of collection) {
    if (!spec.has(endpoint)) {
      problems.push(
        `in the collection but not in the specification: ${endpoint}  ("${name}")`
      );
    }
  }

  if (problems.length > 0) {
    console.error("The collection and the OpenAPI document disagree:\n");
    for (const p of problems) console.error(`  - ${p}`);
    console.error(
      "\nBoth are published to different audiences. Fix whichever is wrong."
    );
    process.exit(1);
  }

  console.log(
    `ok: ${spec.size} endpoints agree between the specification and the collection`
  );
  for (const [endpoint] of [...spec].sort()) console.log(`   ${endpoint}`);
}

main();
