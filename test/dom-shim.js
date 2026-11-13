/**
 * Minimal DOM shim, sufficient for web/client.js (createElement, attributes,
 * listeners, append, replaceWith, replaceChildren). Keeps the test dependency-
 * free so CI does not need jsdom.
 */

class Node {
  constructor(tag) {
    this.tagName = tag?.toUpperCase()
    this.children = []
    this.parent = null
    this.listeners = {}
    this.attributes = {}
    this.dataset = {}
    this._text = ''
    this._checked = false
  }

  get className() { return this.attributes.class ?? '' }
  set className(v) { this.attributes.class = v }
  get type() { return this.attributes.type }
  set type(v) { this.attributes.type = v }

  // Mirrors the browser: setting `checked` does NOT fire a change event;
  // only user interaction (simulated by clickCheck) does.
  get checked() { return this._checked }
  set checked(v) { this._checked = Boolean(v) }
  clickCheck(value = !this._checked) {
    this._checked = value
    this.emit('change', { target: this })
  }

  get indeterminate() { return this._indeterminate }
  set indeterminate(v) { this._indeterminate = Boolean(v) }

  get textContent() {
    if (this.children.length === 0) return this._text
    return this.children.map((c) => c.textContent).join('')
  }
  set textContent(v) { this._text = String(v); this.children = [] }

  setAttribute(k, v) { this.attributes[k] = String(v); if (k.startsWith('data-')) this.dataset[k.slice(5)] = String(v) }
  getAttribute(k) { return this.attributes[k] }
  removeAttribute(k) { delete this.attributes[k] }

  addEventListener(type, fn) { (this.listeners[type] ??= []).push(fn) }
  emit(type, event = {}) {
    for (const fn of this.listeners[type] ?? []) fn({ target: this, preventDefault() {}, stopPropagation() {}, ...event })
  }
  click() { this.emit('click', { target: this }) }

  append(...nodes) {
    for (const node of nodes) {
      if (node == null) continue
      const child = typeof node === 'string' ? Object.assign(new Node('#text'), { _text: node }) : node
      child.parent = this
      this.children.push(child)
    }
  }
  replaceChildren(...nodes) { this.children = []; this.append(...nodes) }
  replaceWith(other) {
    if (!this.parent) return
    const index = this.parent.children.indexOf(this)
    this.parent.children[index] = other
    other.parent = this.parent
  }
  remove() {
    if (!this.parent) return
    this.parent.children = this.parent.children.filter((c) => c !== this)
    this.parent = null
  }
  querySelector(selector) {
    const [tag, cls] = selector.includes('.') ? selector.split('.') : [selector, null]
    return this.findAll(tag || '*', cls)
  }
  findAll(tag, cls) {
    const out = []
    const visit = (node) => {
      for (const child of node.children) {
        const tagOk = !tag || tag === '*' || child.tagName === tag.toUpperCase()
        const clsOk = !cls || (child.attributes.class ?? '').split(/\s+/).includes(cls)
        if (tagOk && clsOk) out.push(child)
        visit(child)
      }
    }
    visit(this)
    return out[0] ?? null
  }
  findAllMatching(tag, cls) {
    const out = []
    const visit = (node) => {
      for (const child of node.children) {
        const tagOk = !tag || child.tagName === tag.toUpperCase()
        const clsOk = !cls || (child.attributes.class ?? '').split(/\s+/).includes(cls)
        if (tagOk && clsOk) out.push(child)
        visit(child)
      }
    }
    visit(this)
    return out
  }
}

export function installDOM() {
  const body = new Node('body')
  const document = {
    body,
    createElement: (tag) => new Node(tag),
  }
  globalThis.document = document
  globalThis.window = globalThis
  return { document, body }
}
