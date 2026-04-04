"use strict";

const Ajv  = require("ajv");
const path = require("node:path");
const fs   = require("node:fs");

const ajv = new Ajv({ allErrors: true, strict: false });

function loadSchema(name) {
  const schemaPath = path.resolve(__dirname, "schemas", `${name}.schema.json`);
  return JSON.parse(fs.readFileSync(schemaPath, "utf8"));
}

/**
 * Validates a parsed JSON object against the named schema.
 * Throws an Error with a descriptive message if validation fails.
 *
 * @param {string} schemaName  e.g. "file-manifest"
 * @param {object} data        parsed JSON object
 */
function validate(schemaName, data) {
  const schema    = loadSchema(schemaName);
  const validator = ajv.compile(schema);
  const valid     = validator(data);
  if (!valid) {
    const errors = validator.errors.map(e => `  ${e.instancePath} ${e.message}`).join("\n");
    throw new Error(`Schema validation failed for "${schemaName}":\n${errors}`);
  }
}

module.exports = { validate };
