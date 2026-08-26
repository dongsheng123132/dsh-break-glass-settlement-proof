import { inspectBreakGlassManifestJson, verifyBreakGlassManifest } from './lib/break-glass-settlement-proof.mjs'
export const name = 'dsh-break-glass-settlement-proof'
export const inject = ['tools']
const renderJson = (_args, value) => [{ type: 'text', text: JSON.stringify(value, null, 2) }]
const define = value => ({ ...value, output: { schema: {}, render: renderJson } })
export function createDefinitions(_ctx = {}, config = {}) {
  const workspaceRoot = config.workspaceRoot || process.cwd()
  return [
    define({ name: 'dsh_break_glass_inspect', description: 'Inspect bounded hashes and counts from an explicit emergency-access settlement.', parameters: { type: 'object', required: ['manifestJson'], properties: { manifestJson: { type: 'string' } }, additionalProperties: false }, execute: async ({ manifestJson }) => inspectBreakGlassManifestJson(manifestJson) }),
    define({ name: 'dsh_break_glass_verify', description: 'Verify supplied break-glass session closure and write a redacted content-addressed report.', parameters: { type: 'object', required: ['manifestPath', 'artifactDir'], properties: { manifestPath: { type: 'string' }, artifactDir: { type: 'string' } }, additionalProperties: false }, execute: async args => verifyBreakGlassManifest({ workspaceRoot, ...args }) })
  ]
}
export function apply(ctx, config = {}) { for (const definition of createDefinitions(ctx, config)) ctx.tools.register(definition) }
