/**
 * Test loader: resolves @deepseek-ai/schemastery to the local stub so plugin
 * wiring tests run in a sandbox where the real dependency tree is unavailable.
 */
const STUB = new URL('./schemastery-stub.js', import.meta.url).href

export async function resolve(specifier, context, next) {
  if (specifier === '@deepseek-ai/schemastery') {
    return { url: STUB, shortCircuit: true, format: 'module' }
  }
  return next(specifier, context)
}
