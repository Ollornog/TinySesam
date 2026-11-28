"""The shell component `<ts-shell layout="top|side" current="/docs">` (T-103): TinySesam's bar on an application's page.

One custom element for both shells. An application puts one script into its `<head>` and the element first thing into
`<body>`:

    <script src="/.tinysesam/shell.js" nonce="…"></script>      (server: the proxy passes /.tinysesam/* through)
    <script src="/auth/shell.js" nonce="…"></script>            (library: TinySesam's router in the same app)
    …
    <ts-shell current="/docs"></ts-shell>

The script restores light/dark before the first paint (the C22 switch, `theme.THEME_JS`), adds `shell.css` (the
`--ts-*` tokens and the host rules) to the document with its own nonce, and defines the element. The element fetches
`topbar.json` beside the script (same origin, the browser's cookies) and draws the bar in its shadow DOM — the markup of
`topbar.render` / `topbar.render_frame` with the same CSS (`topbar.CSS`, linked into the shadow root with the same
nonce), so TinySesam's own pages and the component look alike. `layout` comes from the attribute, else from the answer's
`frame.layout` (`apps[id].layout`, `shell_layout`); `current` marks the link of the page shown (`aria-current=page`).

Differences to the bar of the built-in pages, on purpose: "Sign out" is a link to the sign-out page (`logout.href`; a
form would need TinySesam's CSRF token, which the application's page does not hold), and the brand leads to `/` of the
page's own origin. Strict CSP: no inline handler, no `style=`, every element it adds carries the script's nonce; the
answer's texts are escaped, and a link that does not pass the rule of spec §8 is dropped.
"""
from __future__ import annotations

import hashlib
import json

from fastapi import HTTPException, Request
from fastapi.responses import Response

from . import topbar as _topbar
from .theme import THEME_JS, TOKENS, c22_css

#: The texts the element shows — taken from `auth.t` when the script is served (the instance's language).
_TEXTS = ("bar.links", "bar.menu", "bar.signed_in_as", "bar.account", "bar.theme", "bar.light", "bar.dark",
          "bar.system", "bar.back", "bar.via", "bar.security", "bar.approvals", "bar.approvals_n", "acc.admin", "logout")

# The element. `T` (texts), `LOGO` and `ICON` (markup of `topbar.logo` / `topbar._svg`) are put in by `script()`.
_JS = r"""
(function(){
'use strict';
var me=document.currentScript,nonce=me?(me.nonce||me.getAttribute('nonce')||''):'',
    base=me?me.src.replace(/\/shell\.js(?:[?#].*)?$/,''):'';
(function(){__THEME__})();
if(!document.querySelector('link[data-ts-shell]')){
  var l=document.createElement('link');l.rel='stylesheet';l.href=base+'/shell.css';l.setAttribute('data-ts-shell','');
  if(nonce)l.setAttribute('nonce',nonce);(document.head||document.documentElement).appendChild(l);
}
if(!window.customElements||customElements.get('ts-shell'))return;
var T=__TEXTS__,LOGO=__LOGO__,ICON=__ICONS__;
function e(s){return String(s==null?'':s).replace(/[&<>"']/g,function(c){
  return{'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#x27;'}[c];});}
function t(k,v){var s=T[k]||k;for(var n in(v||{}))s=s.split('{'+n+'}').join(String(v[n]));return s;}
// Spec §8: an absolute http(s) address or a path with exactly one leading slash, no white space or control character.
function safe(h){return typeof h==='string'&&!/[\s\x00-\x1f\x7f]/.test(h)&&
  (/^https?:\/\/[^\/]/i.test(h)||(/^\/(?![\/\\])/.test(h)));}
function links(list){return(Array.isArray(list)?list:[]).filter(function(x){
  return x&&typeof x.title==='string'&&safe(x.href);});}
function href(o){return o&&o.shown!==false&&safe(o.href)?o.href:'';}
function render(d,layout,current){
  var frame=d.frame&&typeof d.frame==='object'&&typeof d.frame.name==='string'&&d.frame.name?d.frame:null;
  var cls='tsbar'+(layout==='side'?' tsside':'')+(frame?' tsframe':'');
  var head='<header class="'+cls+'"><div class="tsbar-in">';
  function cur(h){if(!current||!h)return'';var same=h===current;
    try{var u=new URL(h,location.href);same=same||(u.origin===location.origin&&u.pathname===current);}catch(x){}
    return same?' aria-current="page"':'';}
  var brand,navLinks,label;
  if(frame){
    var via=d.brand&&d.brand!==frame.name?'<span class="tsbar-via">'+e(t('bar.via',{name:d.brand}))+'</span>':'';
    label='<span class="tsbar-app"><span>'+e(frame.name)+'</span>'+via+'</span>';
    if(d.signed_in!==true||!safe(frame.home))return head+'<div class="tsbar-brand">'+label+'</div></div></header>';
    brand='<a class="tsbar-brand tsbar-back" href="'+e(frame.home)+'" aria-label="'+e(t('bar.back',{name:frame.name}))+'">'
      +ICON.back+label+'</a>';
    navLinks=links(frame.links);
  }else{
    brand='<a class="tsbar-brand" href="/">'+LOGO+'<span>'+e(d.brand)+'</span></a>';
    if(d.signed_in!==true)return head+brand+'</div></header>';
    navLinks=links(d.links);
  }
  var nav=navLinks.length?'<nav class="tsbar-links" aria-label="'+e(frame?frame.name:t('bar.links'))+'">'
    +navLinks.map(function(x){return'<a href="'+e(x.href)+'"'+cur(x.href)+'>'+e(x.title)+'</a>';}).join('')+'</nav>':'';
  var items=[],shown=typeof d.name==='string'&&d.name?d.name:'?';
  function item(h,icon,text,key){return'<a class="tsbar-item" href="'+e(h)+'"'+(key&&key===current?' aria-current="page"':cur(h))
    +'>'+ICON[icon]+e(text)+'</a>';}
  if(navLinks.length)items.push('<div class="tsbar-mlinks">'+(frame?'<div class="tsbar-label">'+e(frame.name)+'</div>':'')
    +navLinks.map(function(x){return item(x.href,'link',x.title);}).join('')+'<div class="tsbar-sep"></div></div>');
  var menuLinks=frame?[]:links(d.menu_links);
  if(menuLinks.length)items.push('<div class="tsbar-menulinks">'+menuLinks.map(function(x){return item(x.href,'link',x.title);})
    .join('')+'<div class="tsbar-sep"></div></div>');
  if(href(d.account))items.push(item(d.account.href,frame?'shield':'user',t(frame?'bar.security':'bar.account'),'account'));
  var ap=d.approvals,pending=ap&&typeof ap.pending==='number'&&ap.pending>=0&&safe(ap.href)?ap.pending:null;
  if(pending!==null)items.push(item(ap.href,'approve',pending?t('bar.approvals_n',{n:pending}):t('bar.approvals'),'approvals'));
  if(href(d.admin_panel))items.push(item(d.admin_panel.href,'admin',t('acc.admin'),'admin'));
  if(items.length)items.push('<div class="tsbar-sep"></div>');
  items.push('<div class="tsbar-label" id="tsbar-tl">'+e(t('bar.theme'))+'</div><div class="tsbar-theme" role="group" '
    +'aria-labelledby="tsbar-tl">'+['light','dark','system'].map(function(m){return'<button type="button" data-theme-mode="'
    +m+'" aria-pressed="false">'+ICON[m]+'<span class="tsbar-label-t">'+e(t('bar.'+m))+'</span></button>';}).join('')
    +'</div><div class="tsbar-sep"></div>');
  if(d.logout&&safe(d.logout.href))items.push(item(d.logout.href,'out',t('logout')));
  var menuLabel=t('bar.menu',{name:shown}),count='';
  if(pending){menuLabel+=' — '+t('bar.approvals_n',{n:pending});
    count='<span class="tsbar-count" aria-hidden="true" title="'+e(t('bar.approvals_n',{n:pending}))+'">'+pending+'</span>';}
  var menu='<div class="tsbar-menu"><button type="button" class="tsbar-btn" aria-expanded="false" aria-controls="tsbar-pop" '
    +'aria-label="'+e(menuLabel)+'"><span class="tsbar-av" aria-hidden="true">'+e(String(shown).charAt(0))+'</span>'
    +'<span class="tsbar-name">'+e(shown)+'</span>'+count+ICON.chev+'</button><div class="tsbar-pop" id="tsbar-pop" hidden>'
    +'<div class="tsbar-who">'+e(t('bar.signed_in_as'))+'<b>'+e(shown)+'</b></div>'+items.join('')+'</div></div>';
  return head+brand+nav+menu+'</div></header>';
}
var mq=matchMedia('(prefers-color-scheme: dark)');
function mode(){var m=null;try{m=localStorage.getItem('themeMode');}catch(x){}return m==='light'||m==='dark'?m:'system';}
class TsShell extends HTMLElement{
  static get observedAttributes(){return['layout','current'];}
  connectedCallback(){if(!this.shadowRoot)this.attachShadow({mode:'open'});this._load();}
  attributeChangedCallback(){if(this._data)this._draw();}
  _load(){var self=this;
    fetch(base+'/topbar.json',{credentials:'same-origin',headers:{Accept:'application/json'},cache:'no-store'})
      .then(function(r){return r.ok?r.json():{signed_in:false};})
      .catch(function(){return{signed_in:false};})
      .then(function(d){self._data=d&&typeof d==='object'?d:{signed_in:false};self._draw();
        self.dispatchEvent(new CustomEvent('ts-shell-ready',{bubbles:true}));});}
  _draw(){
    var d=this._data,want=this.getAttribute('layout');
    var layout=want==='top'||want==='side'?want:(d.frame&&(d.frame.layout==='side'||d.frame.layout==='top')?d.frame.layout:'top');
    if(want!==layout){this.setAttribute('layout',layout);return;}
    var css='<link rel="stylesheet" href="'+e(base+'/shell.css')+'"'+(nonce?' nonce="'+e(nonce)+'"':'')+'>';
    this.shadowRoot.innerHTML=css+render(d,layout,this.getAttribute('current')||'');
    this._wire();}
  _wire(){
    var root=this.shadowRoot,bar=root.querySelector('.tsbar'),menu=root.querySelector('.tsbar-menu'),
        btn=root.querySelector('.tsbar-btn'),pop=root.querySelector('.tsbar-pop'),doc=document.documentElement;
    function setOpen(open,back){if(!btn)return;pop.hidden=!open;btn.setAttribute('aria-expanded',open?'true':'false');
      if(!open&&back)btn.focus();}
    if(btn){
      btn.addEventListener('click',function(){setOpen(pop.hidden);});
      if(this._outside){document.removeEventListener('click',this._outside);document.removeEventListener('keydown',this._esc);}
      this._outside=function(ev){if(!pop.hidden&&ev.composedPath().indexOf(menu)<0)setOpen(false);};
      this._esc=function(ev){if(ev.key==='Escape'&&!pop.hidden){ev.preventDefault();setOpen(false,true);}};
      document.addEventListener('click',this._outside);document.addEventListener('keydown',this._esc);
      menu.addEventListener('focusout',function(ev){if(ev.relatedTarget&&!menu.contains(ev.relatedTarget))setOpen(false);});
    }
    function apply(){var m=mode();doc.classList.toggle('dark',m==='dark'||(m==='system'&&mq.matches));
      bar.querySelectorAll('[data-theme-mode]').forEach(function(b){
        b.setAttribute('aria-pressed',b.getAttribute('data-theme-mode')===m?'true':'false');});}
    bar.querySelectorAll('[data-theme-mode]').forEach(function(b){b.addEventListener('click',function(){
      var m=b.getAttribute('data-theme-mode');
      try{if(m==='system')localStorage.removeItem('themeMode');else localStorage.setItem('themeMode',m);}catch(x){}
      apply();});});
    if(!this._live){this._live=true;if(mq.addEventListener)mq.addEventListener('change',apply);
      addEventListener('storage',function(ev){if(ev.key==='themeMode')apply();});}
    apply();}
  disconnectedCallback(){if(this._outside){document.removeEventListener('click',this._outside);
    document.removeEventListener('keydown',this._esc);}}
}
customElements.define('ts-shell',TsShell);
})();
"""


def script(auth) -> str:
    """The text of `shell.js` for this instance: the element with the texts in `lang`, the logo and the icons."""
    texts = {k: auth.t(k) for k in _TEXTS}
    icons = {name: _topbar._svg(name, "tsbar-chev" if name == "chev" else "")
             for name in ("chev", "user", "admin", "light", "dark", "system", "out", "link", "approve", "back", "shield")}
    return (_JS.replace("__THEME__", THEME_JS).replace("__TEXTS__", json.dumps(texts))
            .replace("__LOGO__", json.dumps(_topbar.logo(auth.cfg))).replace("__ICONS__", json.dumps(icons)))


def css(auth) -> str:
    """The text of `shell.css`: the tokens (and the C22 adapter with `c22_stylesheet`), the bar's CSS with its side
    layout and the host rules — one file for the document (tokens, `ts-shell`, the body's room for the side bar) and
    for the shadow root (the bar). `brand_css` stays out, as in `topbar_head`: it may carry rules for TinySesam's own
    pages; an application sets its `--ts-*` values in its own stylesheet."""
    return f"{TOKENS}{c22_css(auth.cfg)}ts-shell{{display:block}}{_topbar.CSS}"


def asset(auth, request: Request, kind: str) -> Response:
    """`shell.js` (`kind` "js") or `shell.css` ("css") — the routes `/auth/shell.*` (router) and `/.tinysesam/shell.*`
    (`_routes_forward`, only for a protected host). 404 with `topbar_enabled=False`. A strong ETag with `no-cache`: the
    browser keeps the file and asks again (304), a changed configuration (language, logo) shows at once."""
    if not getattr(auth.cfg, "topbar_enabled", True):
        raise HTTPException(404, auth.t("api.not_found"))
    body, media_type = (script(auth), "text/javascript") if kind == "js" else (css(auth), "text/css")
    tag = '"' + hashlib.sha256(body.encode("utf-8")).hexdigest()[:32] + '"'
    headers = {"Cache-Control": "no-cache", "ETag": tag, "X-Content-Type-Options": "nosniff"}
    if tag in [v.strip() for v in (request.headers.get("if-none-match") or "").split(",")]:
        return Response(status_code=304, headers=headers)
    return Response(body, media_type=media_type, headers=headers)
