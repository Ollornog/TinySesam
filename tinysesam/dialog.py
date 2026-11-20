"""Own dialogs instead of the browser's system dialogs `alert`, `confirm` and `prompt` (T-35).

The browser's system dialogs cannot be styled, block the whole tab, offer no copy button and show an API key in
a plain text field that invites a mis-click. Every built-in page that asks or tells something uses this one building
block instead: a native `<dialog>` opened with `showModal()`, styled only through the `--ts-*` tokens, without
inline handlers (the strict nonce CSP covers the `<style>`/`<script>` it ships).

In the browser it defines four Promise-based functions (and `tsCopy`):

    await tsAlert(text)                         # → undefined, once closed
    await tsConfirm(text, {danger: true})       # → true (OK) | false (Cancel, Escape)
    await tsPrompt(text, value, {type})         # → the entered string | null (Cancel, Escape)
    await tsSecret(title, value, note)          # a secret shown once, with a copy button
    await tsCopy(value, field)                  # → true (clipboard) | false (text selected in `field`)

Keyboard: Tab stays inside the dialog, Escape cancels (never confirms), Enter in a field confirms, and the focus goes
back to the element that opened it. Copying uses `navigator.clipboard.writeText`; without it (plain HTTP, an old
browser) the text is pre-selected in its read-only field, and the dialog says to press Ctrl+C. The value is never
put into a URL, `localStorage` or the console.

An own template (`auth.set_template`) gets the same building block as `ctx["dialog"]` (an HTML string with a
`<style>` and a `<script>`; `render_page` gives both the response's nonce).
"""
from __future__ import annotations

import json

#: Text keys of the dialog (messages.py, en + de).
KEYS = ("dlg.ok", "dlg.cancel", "dlg.close", "dlg.copy", "dlg.copied", "dlg.copy_manual")

CSS = """
dialog.tsdlg{width:440px;max-width:calc(100vw - 32px);box-sizing:border-box;margin:auto;padding:20px;
  background:var(--ts-surface);color:var(--ts-ink);border:1px solid var(--ts-line);border-radius:var(--ts-radius);
  font-family:var(--ts-font);font-size:14px;line-height:1.45}
dialog.tsdlg::backdrop{background:var(--ts-image-overlay-edge)}
dialog.tsdlg *{box-sizing:border-box}
dialog.tsdlg .tsdlg-title{font-size:16px;font-weight:600;margin:0 0 10px}
dialog.tsdlg .tsdlg-text{margin:0 0 14px;white-space:pre-wrap;overflow-wrap:anywhere}
dialog.tsdlg .tsdlg-note{margin:0 0 12px;color:var(--ts-muted);font-size:13px}
dialog.tsdlg .tsdlg-field{display:block;width:100%;margin:0 0 14px;padding:9px 11px;font:inherit;
  background:var(--ts-field-bg);color:var(--ts-ink);border:1px solid var(--ts-field-line);border-radius:8px}
dialog.tsdlg textarea.tsdlg-field{font-family:var(--ts-mono);font-size:13px;resize:none;overflow:hidden;
  word-break:break-all}
dialog.tsdlg .tsdlg-row{display:flex;flex-wrap:wrap;gap:8px;justify-content:flex-end;align-items:center}
dialog.tsdlg .tsdlg-status{margin-right:auto;font-size:13px;color:var(--ts-ok-ink)}
dialog.tsdlg .tsdlg-status.tsdlg-manual{color:var(--ts-warn-ink)}
dialog.tsdlg button{width:auto;margin:0;padding:9px 16px;border:0;border-radius:8px;font:inherit;cursor:pointer;
  background:var(--ts-accent);color:var(--ts-accent-ink)}
dialog.tsdlg button.tsdlg-sec{background:var(--ts-neutral);color:var(--ts-neutral-ink)}
dialog.tsdlg button.tsdlg-danger{background:var(--ts-danger);color:var(--ts-accent-ink)}
dialog.tsdlg button:focus-visible,dialog.tsdlg .tsdlg-field:focus-visible{outline:2px solid var(--ts-link);
  outline-offset:2px}
"""

# One IIFE, defined once per page even if a page includes the building block twice. Everything is built with
# createElement/textContent — a text from the server (a rejection reason, a username) never becomes markup.
_JS = """
(function(){
if(window.tsAlert)return;
const T=__TEXTS__;
let seq=0;
function el(tag,cls,text){const e=document.createElement(tag);if(cls)e.className=cls;
  if(text!=null)e.textContent=String(text);return e}
function canClip(){return !!(navigator.clipboard&&navigator.clipboard.writeText&&window.isSecureContext)}
function pick(field){field.focus();
  if(typeof field.select==='function'){field.select();return}
  const r=document.createRange();r.selectNodeContents(field);const s=getSelection();s.removeAllRanges();s.addRange(r)}
async function tsCopy(value,field){
  if(canClip()){try{await navigator.clipboard.writeText(String(value));return true}catch(e){}}
  if(field)pick(field);
  return false}
function show(o){return new Promise(resolve=>{
  const back=document.activeElement,id='tsdlg'+(++seq);
  const d=el('dialog','tsdlg');
  d.setAttribute('aria-modal','true');
  if(o.kind!=='secret')d.setAttribute('role','alertdialog');
  let head=null;
  if(o.title){head=el('h2','tsdlg-title',o.title);head.id=id+'h';d.append(head)}
  const text=el('p','tsdlg-text',o.text);text.id=id+'t';
  if(o.text!=null&&o.text!=='')d.append(text);
  d.setAttribute('aria-labelledby',head?head.id:text.id);
  if(head&&d.contains(text))d.setAttribute('aria-describedby',text.id);
  let field=null,status=null;
  if(o.kind==='prompt'){field=el('input','tsdlg-field');field.type=o.type||'text';field.value=o.value==null?'':String(o.value);
    field.setAttribute('aria-labelledby',text.id);field.autocomplete=o.type==='password'?'new-password':'off';d.append(field)}
  if(o.kind==='secret'){const v=String(o.value==null?'':o.value);
    field=el('textarea','tsdlg-field');field.readOnly=true;field.value=v;field.spellcheck=false;
    field.rows=Math.min(12,Math.max(1,v.split('\\n').length));field.setAttribute('aria-labelledby',head?head.id:text.id);
    d.append(field);if(o.note)d.append(el('p','tsdlg-note',o.note))}
  const row=el('div','tsdlg-row');
  let copy=null,cancel=null;
  const fit=o.kind==='secret'?()=>{field.style.height='auto';field.style.height=(field.scrollHeight+2)+'px'}:null;
  if(o.kind==='secret'){status=el('span','tsdlg-status');status.setAttribute('role','status');
    status.setAttribute('aria-live','polite');row.append(status);
    copy=el('button','tsdlg-copy',T['dlg.copy']);copy.type='button';row.append(copy)}
  if(o.kind==='confirm'||o.kind==='prompt'){cancel=el('button','tsdlg-sec tsdlg-cancel',T['dlg.cancel']);cancel.type='button';row.append(cancel)}
  // With a secret, copying is the main action and „Done“ the secondary one.
  const ok=el('button','tsdlg-ok'+(o.danger?' tsdlg-danger':'')+(o.kind==='secret'?' tsdlg-sec':''),
    o.kind==='secret'?T['dlg.close']:T['dlg.ok']);
  ok.type='button';row.append(ok);d.append(row);
  // What Cancel/Escape yields — never the confirming value.
  const nope=o.kind==='confirm'?false:(o.kind==='prompt'?null:undefined);
  const yes=()=>o.kind==='confirm'?true:(o.kind==='prompt'?field.value:undefined);
  let done=false;
  function finish(v){if(done)return;done=true;if(fit)removeEventListener('resize',fit);if(d.open)d.close();d.remove();
    if(back&&typeof back.focus==='function'&&document.contains(back))back.focus();
    resolve(v)}
  ok.addEventListener('click',()=>finish(yes()));
  if(cancel)cancel.addEventListener('click',()=>finish(nope));
  // Escape fires `cancel`, then `close`: both end as Cancel.
  d.addEventListener('cancel',e=>{e.preventDefault();finish(nope)});
  d.addEventListener('close',()=>finish(nope));
  if(copy)copy.addEventListener('click',async()=>{const fine=await tsCopy(field.value,field);
    status.textContent=fine?T['dlg.copied']:T['dlg.copy_manual'];
    status.className='tsdlg-status'+(fine?'':' tsdlg-manual');if(fine)copy.focus()});
  d.addEventListener('keydown',e=>{
    if(e.key==='Enter'&&o.kind==='prompt'&&e.target===field){e.preventDefault();finish(yes());return}
    if(e.key!=='Tab')return;
    // Focus trap: Tab and Shift+Tab cycle through the dialog's own controls.
    const f=[...d.querySelectorAll('button,input,textarea')].filter(x=>!x.disabled);
    if(!f.length)return;
    const first=f[0],last=f[f.length-1];
    if(e.shiftKey&&(document.activeElement===first||!d.contains(document.activeElement))){e.preventDefault();last.focus()}
    else if(!e.shiftKey&&(document.activeElement===last||!d.contains(document.activeElement))){e.preventDefault();first.focus()}});
  document.body.append(d);d.showModal();
  // The secret's field grows to its text (a long key wraps), also when the window changes (a phone turned) —
  // set through the CSSOM, which the CSP allows.
  if(fit){fit();addEventListener('resize',fit)}
  if(o.kind==='prompt'){field.focus();field.select()}
  else if(o.kind==='secret'){if(canClip())copy.focus();else pick(field)}
  else ok.focus()})}
window.tsCopy=tsCopy;
window.tsAlert=text=>show({kind:'alert',text});
window.tsConfirm=(text,opt)=>show({kind:'confirm',text,danger:!!(opt&&opt.danger)});
window.tsPrompt=(text,value,opt)=>show({kind:'prompt',text,value,type:opt&&opt.type});
window.tsSecret=(title,value,note)=>show({kind:'secret',title,value,note});
})();
"""


def texts(auth) -> dict:
    """The dialog texts in the language of the running config (keys without the `dlg.` prefix stay as they are)."""
    return {k: auth.t(k) for k in KEYS}


def script(auth) -> str:
    """The dialog JavaScript without the `<script>` tag (for a page that already has its own block)."""
    # `<` masked: an own translation (`add_messages`) with "</script>" would otherwise end the block.
    return _JS.replace("__TEXTS__", json.dumps(texts(auth), ensure_ascii=False).replace("<", "\\u003c"))


def assets(auth) -> str:
    """`<style>` + `<script>` of the building block — what a page includes once to use the dialogs."""
    return f"<style>{CSS}</style><script>{script(auth)}</script>"
