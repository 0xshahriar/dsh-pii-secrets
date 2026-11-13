/**
 * Test-only stub for @deepseek-ai/schemastery.
 *
 * The real package's dependency chain cannot be installed in this sandbox, so
 * this stub implements exactly the surface src/index.js uses — object, string,
 * number, boolean, union, .default — including real default-filling, so plugin
 * wiring tests run real code paths instead of being skipped.
 */
class Schema {
  constructor(build, fallback = undefined) {
    this._build = build
    this._default = fallback
    this._hasDefault = arguments.length > 1
  }
  default(value) {
    return new Schema(this._build, value)
  }
}

function primitive(test, name) {
  return () => new Schema((v) => {
    if (v === undefined) return undefined
    if (!test(v)) throw new TypeError(`expected ${name}, got ${typeof v}`)
    return v
  })
}

const Schema_ = {
  string: primitive((v) => typeof v === 'string', 'string'),
  number: primitive((v) => typeof v === 'number' && !Number.isNaN(v), 'number'),
  boolean: primitive((v) => typeof v === 'boolean', 'boolean'),
  union: (values) => new Schema((v) => {
    if (v === undefined) return undefined
    if (!values.includes(v)) throw new TypeError(`expected one of ${values.join(', ')}`)
    return v
  }),
  object(dict) {
    return new Schema((raw = {}) => {
      const out = {}
      for (const [key, schema] of Object.entries(dict)) {
        const value = raw[key]
        out[key] = value === undefined && schema._hasDefault ? schema._default : schema._build(value)
      }
      return out
    })
  },
}

export default Schema_
