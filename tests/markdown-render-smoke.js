const fs=require('fs'),vm=require('vm');
class Node {
  constructor(tag=''){this.tagName=tag.toUpperCase();this.children=[];this.dataset={};this.classes=[];this.classList={add:(...x)=>{this.classes.push(...x)}};this._text='';this._className='';}
  append(...x){this.children.push(...x)}
  set textContent(v){this._text=String(v)}
  get textContent(){return this._text}
  set className(v){this._className=String(v)}
  get className(){return this._className}
}
function makeContext(){
  const document={createElement:t=>new Node(t),createTextNode:t=>({textContent:String(t)}),querySelector:()=>new Node(),querySelectorAll:()=>[],addEventListener:()=>{},body:new Node('body')};
  return {document,console};
}
function load(src,from,to){
  const ctx=makeContext();
  const start=src.indexOf(from),end=src.indexOf(to,start);
  if(start<0||end<0)throw new Error('could not slice '+from+'..'+to);
  vm.createContext(ctx);
  vm.runInContext(src.slice(start,end),ctx);
  return ctx;
}
function byClass(node,cls,out=[]){
  if(String(node.className||'').split(/\s+/).includes(cls))out.push(node);
  for(const c of node.children||[])byClass(c,cls,out);
  return out;
}
const src=fs.readFileSync('content/assets/js/script.js','utf8');
const page=fs.readFileSync('content/index.html','utf8');
if(page.includes('Implement, investigate')||page.includes('drop or paste images'))throw new Error('agent prompt placeholder returned');

// ---- Markdown + tool rendering ----
const ctx=load(src,'function appendAgentMarkdownInline','function renderAgentFeed');

// 1. Markdown smoke (existing behaviour preserved).
{
  const row=new Node('div');
  ctx.renderAgentMarkdown(row,'## Heading\n\n**bold** and `code`\n\n- one\n- two');
  const flat=JSON.stringify(row);
  for(const want of ['agent-md-heading','## Heading','agent-md-gap','**bold**','`code`','"UL"'])if(!flat.includes(want))throw new Error('missing '+want);
}

// 2. Underscore-delimited text must stay literal.
{
  const row=new Node('div');
  ctx.renderAgentMarkdown(row,'Use foo_bar and my_var and __init__ and C:/Users/Nick');
  const flat=JSON.stringify(row);
  if(flat.includes('"EM"')||flat.includes('"STRONG"'))throw new Error('underscore text was emphasised');
  if(!flat.includes('foo_bar')||!flat.includes('__init__'))throw new Error('underscore identifiers not preserved');
}

// 3. Quoted-string highlighting (escaped-aware; single quotes need a preceding space).
{
  const cases=[
    ['"this should be highlighted"','"this should be highlighted"'],
    ["Value: 'as should this'","'as should this'"],
    ["Value: 'that\\'s counted too'","'that\\'s counted too'"],
    ['"say \\"hello\\""','"say \\"hello\\""'],
    ["Path: 'C:\\Users\\Nick'","'C:\\Users\\Nick'"],
    ['"single quote \' inside double quotes"','"single quote \' inside double quotes"'],
    ["Value: 'double quote \" inside single quotes'","'double quote \" inside single quotes'"],
  ];
  for(const [text,want] of cases){
    const row=new Node('div');
    ctx.renderAgentMarkdown(row,text);
    const quotes=byClass(row,'agent-md-quote');
    if(quotes.length!==1||quotes[0].textContent!==want)throw new Error('quote mismatch for '+JSON.stringify(text)+' got '+quotes.length+' spans');
  }
  const row=new Node('div');
  ctx.renderAgentMarkdown(row,'an unterminated "string and \'other');
  if(byClass(row,'agent-md-quote').length)throw new Error('unterminated string was highlighted');
  {
    const prose=['this isn\'t a sentence we want highlighted just cause it\'s got single quotes',"Nick's project","can't match through another apostrophe later","rock'n'roll","foo'bar'"];
    for(const text of prose){
      const r=new Node('div');
      ctx.renderAgentMarkdown(r,text);
      if(byClass(r,'agent-md-quote').length)throw new Error('apostrophe prose was highlighted: '+text);
    }
  }
  {
    const r=new Node('div');
    ctx.renderAgentMarkdown(r,"Use 'this quoted block' here");
    const quotes=byClass(r,'agent-md-quote');
    if(quotes.length!==1||quotes[0].textContent!=="'this quoted block'")throw new Error('space-prefixed quote handling wrong');
  }
}

// 4. Tool-status events (live and restored shapes).
{
  const toolCases=['↳ bash · running','↳ bash · completed','↳ bash · failed','↳ read · completed','↳ gh · failed','↳ bash · queued','↳ bash · cancelled','↳ bash · interrupted'];
  for(const line of toolCases){
    const row=new Node('div');
    ctx.renderAgentToolEvent(row,line+'\n$ some command\noutput');
    if(!row.children.length||row.children[0].className!=='agent-tool-head')throw new Error('tool not structured: '+line);
    const name=byClass(row,'agent-tool-name')[0],status=byClass(row,'agent-tool-status')[0];
    if(!name||name.textContent!==line.split(' · ')[0].replace('↳ ',''))throw new Error('tool name wrong: '+line);
    if(!status||!status.className.includes(line.split(' · ')[1]))throw new Error('tool status class missing: '+line);
  }
  // Regression-era stored text renders as a tool event.
  {
    const row=ctx.agentEventNode({kind:'assistant',text:'Provider-reported tool event\n↳ bash · failed\n$ gh auth status\noutput'});
    if(!row.children.length||row.children[0].className!=='agent-tool-head')throw new Error('regression-era tool text not restored');
  }
  // Ordinary assistant prose containing an arrow must NOT be reinterpreted.
  {
    const row=ctx.agentEventNode({kind:'assistant',text:'I used the ↳ symbol in prose, not a tool event.'});
    if(row.children.length&&row.children[0].className==='agent-tool-head')throw new Error('prose arrow was misinterpreted');
  }
}

// ---- Event classification used by the streaming run loop ----
{
  if(ctx.agentEventKind({type:'error',data:{message:'x'}})!=='error')throw new Error('error classification');
  if(ctx.agentEventKind({type:'diagnostic',data:{message:'x'}})!=='error')throw new Error('diagnostic classification');
  if(ctx.agentEventKind({type:'done',data:{}})!=='done')throw new Error('done classification');
  if(ctx.agentEventKind({type:'opencode',data:{type:'tool',part:{type:'tool',tool:'bash'}}})!=='tool')throw new Error('tool classification');
  if(ctx.agentEventKind({type:'opencode',data:{type:'text',part:{type:'text',text:'hi'}}})!=='assistant')throw new Error('text classification');
}

// ---- summarizeAgentTool/summarizeAgentEvent produce an un-prefixed ↳ header ----
{
  const ctx3=load(src,'function clippedAgentText','function agentReadDataURL');
  const ev={type:'opencode',data:{type:'tool',part:{type:'tool',tool:'bash',state:{status:'failed',input:{command:'gh auth status'},output:'x'}}}};
  const text=ctx3.summarizeAgentEvent(ev);
  if(!text.startsWith('↳ bash · failed'))throw new Error('summarize tool text wrong: '+JSON.stringify(text));
}

console.log('warden markdown/tool render smoke: ok');
