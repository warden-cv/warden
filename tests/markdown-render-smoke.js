const fs=require('fs'),vm=require('vm');
class Node{constructor(tag=''){this.tagName=tag.toUpperCase();this.children=[];this.dataset={};this._text=''}append(...x){this.children.push(...x)}set textContent(v){this._text=String(v)}get textContent(){return this._text}set className(v){this._className=v}get className(){return this._className||''}}
const document={createElement:t=>new Node(t),createTextNode:t=>({textContent:String(t)})};
const src=fs.readFileSync('content/assets/js/script.js','utf8'),start=src.indexOf('function appendAgentMarkdownInline'),end=src.indexOf('function renderAgentToolEvent',start),ctx={document,console};vm.createContext(ctx);vm.runInContext(src.slice(start,end),ctx);
const row=new Node('div');ctx.renderAgentMarkdown(row,'## Heading\n\n**bold** and `code`\n\n- one\n- two');
const flat=JSON.stringify(row);
for(const want of ['agent-md-heading','## Heading','agent-md-gap','**bold**','`code`','"UL"'])if(!flat.includes(want))throw new Error('missing '+want);
console.log('warden markdown render smoke: ok');
