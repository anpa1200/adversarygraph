import { useState } from 'react';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { pipelineApi, type DetectionVersion } from '@/api/client';
import { Header } from '@/components/Layout/Header';
import { useAppStore } from '@/store';

type Tab = 'sources' | 'observables' | 'sandbox' | 'detections' | 'imports' | 'audit';
const input = 'w-full bg-gray-800 border border-gray-700 rounded px-3 py-2 text-xs text-gray-200 outline-none focus:border-mitre-accent';

export function Pipeline() {
  const [tab,setTab]=useState<Tab>('sources');
  const {data:me}=useQuery({queryKey:['pipeline-me'],queryFn:pipelineApi.me});
  return <div className="flex flex-col h-full"><Header title="Intelligence Pipeline" />
    <div className="px-6 py-2 border-b border-gray-800 text-[11px] text-gray-500">Signed in as <span className="text-gray-300">{me?.name ?? 'local'}</span> · {(me?.roles ?? []).join(', ')} · Automated inputs remain pending until analyst review.</div>
    <div className="flex gap-5 px-6 border-b border-gray-700">{(['sources','observables','sandbox','detections','imports','audit'] as Tab[]).map(item=><button key={item} onClick={()=>setTab(item)} className={`py-3 capitalize text-sm border-b-2 ${tab===item?'border-mitre-accent text-white':'border-transparent text-gray-500'}`}>{item}</button>)}</div>
    <div className="flex-1 overflow-y-auto p-6">{tab==='sources'&&<Sources/>}{tab==='observables'&&<Observables/>}{tab==='sandbox'&&<SandboxBehaviors/>}{tab==='detections'&&<DetectionStudio/>}{tab==='imports'&&<Imports/>}{tab==='audit'&&<Audit/>}</div>
  </div>;
}

function Sources(){
  const qc=useQueryClient(); const {data=[]}=useQuery({queryKey:['pipeline-sources'],queryFn:pipelineApi.sources}); const {data:runs=[]}=useQuery({queryKey:['pipeline-runs'],queryFn:pipelineApi.runs});
  const [name,setName]=useState('');const[url,setUrl]=useState('');
  const create=useMutation({mutationFn:()=>pipelineApi.createSource({name,kind:'rss',url,enabled:true,interval_minutes:60,config:{}}),onSuccess:()=>{setName('');setUrl('');qc.invalidateQueries({queryKey:['pipeline-sources']})}});
  const run=useMutation({mutationFn:pipelineApi.runSource,onSuccess:()=>{qc.invalidateQueries({queryKey:['pipeline-runs']});qc.invalidateQueries({queryKey:['operations-intake']});qc.invalidateQueries({queryKey:['pipeline-observables']})}});
  return <div className="max-w-7xl mx-auto grid lg:grid-cols-[1fr_380px] gap-4"><Panel title="Collection Sources"><div className="grid md:grid-cols-[1fr_2fr_auto] gap-2 p-3"><input className={input} value={name} onChange={e=>setName(e.target.value)} placeholder="Feed name"/><input className={input} value={url} onChange={e=>setUrl(e.target.value)} placeholder="HTTPS RSS / Atom URL"/><button className="primary" disabled={!name||!url} onClick={()=>create.mutate()}>Add RSS</button></div>{data.map(row=><div key={row.id} className="flex items-center gap-3 p-3 border-t border-gray-800"><div className="flex-1"><b className="block text-sm text-gray-200">{row.name}</b><small className="block truncate text-gray-600">{row.kind.toUpperCase()} · {row.url}</small></div><button className="primary" onClick={()=>run.mutate(row.id)} disabled={run.isPending||row.kind!=='rss'}>Run</button></div>)}</Panel><Panel title="Recent Runs">{runs.map(row=><div key={row.id} className="p-3 border-b border-gray-800 text-xs"><b className={row.status==='complete'?'text-green-400':'text-red-400'}>{row.status}</b><span className="text-gray-500"> · {row.items_created} intake · {row.observables_created} observables</span>{row.error&&<p className="text-red-500 mt-1">{row.error}</p>}</div>)}</Panel></div>;
}

function Observables(){
  const qc=useQueryClient();const{data=[]}=useQuery({queryKey:['pipeline-observables'],queryFn:pipelineApi.observables});const[type,setType]=useState('domain');const[value,setValue]=useState('');
  const create=useMutation({mutationFn:()=>pipelineApi.createObservable({type,value,status:'new',confidence:0,tags:[],source_refs:[]}),onSuccess:()=>{setValue('');qc.invalidateQueries({queryKey:['pipeline-observables']})}});
  const enrich=useMutation({mutationFn:pipelineApi.enrich,onSuccess:()=>qc.invalidateQueries({queryKey:['pipeline-audit']})});
  return <div className="max-w-7xl mx-auto"><Panel title="Observable Workbench"><div className="grid md:grid-cols-[140px_1fr_auto] gap-2 p-3"><select className={input} value={type} onChange={e=>setType(e.target.value)}>{['domain','ipv4','sha256','md5','cve','url'].map(v=><option key={v}>{v}</option>)}</select><input className={input} value={value} onChange={e=>setValue(e.target.value)} placeholder="Observable value"/><button className="primary" disabled={!value} onClick={()=>create.mutate()}>Add</button></div><div className="grid lg:grid-cols-2">{data.map(row=><div key={row.id} className="flex gap-3 p-3 border-t border-gray-800"><span className="font-mono text-xs text-mitre-accent w-16">{row.type}</span><div className="flex-1 min-w-0"><b className="block truncate text-xs text-gray-300">{row.value}</b><small className="text-gray-600">{row.status} · confidence {row.confidence} · {row.source_refs.length} sources</small></div><button className="secondary" onClick={()=>enrich.mutate(row.id)}>Enrich</button></div>)}</div></Panel></div>;
}

function SandboxBehaviors(){
  const qc=useQueryClient();const {addTechniques,replaceTechniques}=useAppStore();const{data:sources=[]}=useQuery({queryKey:['pipeline-sources'],queryFn:pipelineApi.sources});const{data:behaviors=[]}=useQuery({queryKey:['pipeline-sandbox-behaviors'],queryFn:pipelineApi.sandboxBehaviors});const[name,setName]=useState('');const[url,setUrl]=useState('');
  const sandboxSources=sources.filter(source=>source.kind==='sandbox');
  const create=useMutation({mutationFn:()=>pipelineApi.createSource({name,kind:'sandbox',url,enabled:true,interval_minutes:1440,config:{limit:100}}),onSuccess:()=>{setName('');setUrl('');qc.invalidateQueries({queryKey:['pipeline-sources']})}});
  const sync=useMutation({mutationFn:pipelineApi.runSource,onSuccess:()=>{qc.invalidateQueries({queryKey:['pipeline-runs']});qc.invalidateQueries({queryKey:['pipeline-sandbox-behaviors']});qc.invalidateQueries({queryKey:['pipeline-observables']});qc.invalidateQueries({queryKey:['pipeline-sources']})}});
  const showOnMatrix=(ids:string[])=>{replaceTechniques(ids);window.location.href='/navigator'};
  return <div className="max-w-7xl mx-auto grid lg:grid-cols-[420px_1fr] gap-4">
    <Panel title="Sandbox Behavior Feeds">
      <div className="p-3 space-y-3">
        <p className="text-xs leading-relaxed text-gray-500">Connect a private JSON export from CAPE, Cuckoo, ANY.RUN-style gateways, or another sandbox aggregator. The sync stores sample hashes as observables and attaches behavior enrichment with verdicts, signatures, processes, network artifacts, and ATT&CK IDs.</p>
        <input className={input} value={name} onChange={e=>setName(e.target.value)} placeholder="Feed name"/>
        <input className={input} value={url} onChange={e=>setUrl(e.target.value)} placeholder="https://sandbox.local/reports.json"/>
        <button className="primary" disabled={!name.trim()||!url.trim()||create.isPending} onClick={()=>create.mutate()}>{create.isPending?'Adding...':'Add Sandbox Feed'}</button>
        {create.error&&<p className="text-xs text-red-300">{String(create.error)}</p>}
        {sync.error&&<p className="text-xs text-red-300">{String(sync.error)}</p>}
      </div>
      {sandboxSources.map(source=><div key={source.id} className="flex items-center gap-3 border-t border-gray-800 p-3">
        <div className="min-w-0 flex-1"><b className="block truncate text-sm text-gray-200">{source.name}</b><small className="block truncate text-[10px] text-gray-600">{source.url}</small></div>
        <button className="secondary" onClick={()=>sync.mutate(source.id)} disabled={sync.isPending}>{sync.variables===source.id?'Syncing':'Sync'}</button>
      </div>)}
      {!sandboxSources.length&&<div className="border-t border-gray-800 p-3 text-xs text-gray-600">No sandbox behavior feeds connected yet.</div>}
    </Panel>
    <Panel title={`Recent Sandbox Behavior (${behaviors.length})`}>
      <div className="divide-y divide-gray-800">
        {behaviors.map(item=><article key={item.id} className="p-3">
          <div className="flex flex-wrap items-start justify-between gap-3">
            <div className="min-w-0">
              <div className="flex flex-wrap items-center gap-2">
                <span className={`rounded px-2 py-1 text-[10px] font-semibold ${item.verdict==='malicious'?'bg-red-950/50 text-red-300':item.verdict==='suspicious'?'bg-amber-950/50 text-amber-300':'bg-gray-800 text-gray-400'}`}>{item.verdict}</span>
                <b className="break-all font-mono text-xs text-gray-200">{item.observable}</b>
              </div>
              <small className="mt-1 block text-[10px] text-gray-600">{item.provider} · confidence {item.confidence} · score {item.score ?? '-'} · {item.malware_family || 'unknown family'}</small>
            </div>
            {item.source_url&&<a href={item.source_url} target="_blank" rel="noreferrer" className="secondary">Report ↗</a>}
          </div>
          {item.ttps.length>0&&<div className="mt-3 flex flex-wrap gap-1.5">{item.ttps.slice(0,16).map(ttp=><button key={ttp} onClick={()=>showOnMatrix([ttp])} className="rounded bg-red-950/40 px-1.5 py-0.5 font-mono text-[10px] text-red-300 hover:bg-red-900/60">{ttp}</button>)}<button onClick={()=>addTechniques(item.ttps)} className="secondary">Add TTPs</button><button onClick={()=>showOnMatrix(item.ttps)} className="secondary">Matrix</button></div>}
          {item.signatures.length>0&&<div className="mt-3 grid gap-1">{item.signatures.slice(0,4).map(sig=><div key={`${sig.source}-${sig.name}`} className="rounded border border-gray-800 bg-gray-950/40 px-2 py-1 text-xs text-gray-400">{sig.name}{sig.severity&&<span className="ml-2 text-[10px] text-amber-300">{sig.severity}</span>}</div>)}</div>}
          {item.processes.length>0&&<p className="mt-2 line-clamp-2 font-mono text-[10px] text-gray-600">{item.processes.slice(0,3).join(' | ')}</p>}
          <div className="mt-2 flex flex-wrap gap-1.5">{[...(item.network.domains??[]),...(item.network.ips??[])].slice(0,8).map(value=><span key={value} className="rounded bg-gray-800 px-1.5 py-0.5 text-[10px] text-gray-500">{value}</span>)}</div>
        </article>)}
        {!behaviors.length&&<Empty text="No sandbox behavior enrichments yet. Add a sandbox JSON feed and run sync."/>}
      </div>
    </Panel>
  </div>;
}

function DetectionStudio(){
  const qc=useQueryClient();const{data=[]}=useQuery({queryKey:['pipeline-detection-versions'],queryFn:pipelineApi.versions});const{data:sources=[]}=useQuery({queryKey:['pipeline-sources'],queryFn:pipelineApi.sources});const[title,setTitle]=useState('');const[ttp,setTtp]=useState('T1059.001');const[format,setFormat]=useState('sigma');const[active,setActive]=useState<DetectionVersion|null>(null);const[feedName,setFeedName]=useState('');const[feedUrl,setFeedUrl]=useState('');const[feedKind,setFeedKind]=useState<'sigma'|'yara'>('sigma');
  const generate=useMutation({mutationFn:()=>pipelineApi.generate({title,technique_id:ttp,format,telemetry:['process_creation']}),onSuccess:row=>{setActive(row);qc.invalidateQueries({queryKey:['pipeline-detection-versions']})}});
  const validate=useMutation({mutationFn:()=>pipelineApi.validate(active!.format,active!.content),onSuccess:validation=>active&&setActive({...active,validation})});
  const createDefaults=useMutation({mutationFn:pipelineApi.createDefaultRuleFeeds,onSuccess:()=>qc.invalidateQueries({queryKey:['pipeline-sources']})});
  const createFeed=useMutation({mutationFn:()=>pipelineApi.createSource({name:feedName,kind:feedKind,url:feedUrl,enabled:true,interval_minutes:1440,config:{limit:250}}),onSuccess:()=>{setFeedName('');setFeedUrl('');qc.invalidateQueries({queryKey:['pipeline-sources']})}});
  const syncFeed=useMutation({mutationFn:pipelineApi.runSource,onSuccess:()=>{qc.invalidateQueries({queryKey:['pipeline-runs']});qc.invalidateQueries({queryKey:['pipeline-detection-versions']});qc.invalidateQueries({queryKey:['pipeline-sources']})}});
  const ruleFeeds=sources.filter(source=>source.kind==='sigma'||source.kind==='yara');
  return <div className="max-w-7xl mx-auto grid lg:grid-cols-[420px_1fr] gap-4">
    <div className="space-y-4">
      <Panel title="Connect Sigma / YARA Rule Feeds">
        <div className="p-3 space-y-3">
          <p className="text-xs leading-relaxed text-gray-500">Connect raw rule files, URL lists, or GitHub tree URLs. Imported rules are mapped to ATT&CK when tags or text contain technique IDs.</p>
          <button className="primary" onClick={()=>createDefaults.mutate()} disabled={createDefaults.isPending}>{createDefaults.isPending?'Adding...':'Add SigmaHQ default'}</button>
          <div className="grid gap-2">
            <input className={input} value={feedName} onChange={e=>setFeedName(e.target.value)} placeholder="Feed name"/>
            <input className={input} value={feedUrl} onChange={e=>setFeedUrl(e.target.value)} placeholder="Raw file, URL list, or GitHub tree URL"/>
            <div className="grid grid-cols-[1fr_auto] gap-2">
              <select className={input} value={feedKind} onChange={e=>setFeedKind(e.target.value as typeof feedKind)}><option value="sigma">Sigma</option><option value="yara">YARA</option></select>
              <button className="primary" disabled={!feedName.trim()||!feedUrl.trim()||createFeed.isPending} onClick={()=>createFeed.mutate()}>Add Feed</button>
            </div>
          </div>
          {createFeed.error&&<p className="text-xs text-red-300">{String(createFeed.error)}</p>}
          {syncFeed.error&&<p className="text-xs text-red-300">{String(syncFeed.error)}</p>}
        </div>
        {ruleFeeds.map(source=><div key={source.id} className="flex items-center gap-3 border-t border-gray-800 p-3">
          <div className="min-w-0 flex-1"><b className="block truncate text-sm text-gray-200">{source.name}</b><small className="block truncate text-[10px] text-gray-600">{source.kind.toUpperCase()} · {source.url}</small></div>
          <button className="secondary" onClick={()=>syncFeed.mutate(source.id)} disabled={syncFeed.isPending}>{syncFeed.variables===source.id?'Syncing':'Sync'}</button>
        </div>)}
        {!ruleFeeds.length&&<div className="border-t border-gray-800 p-3 text-xs text-gray-600">No Sigma/YARA feeds connected yet.</div>}
      </Panel>
      <Panel title="Generate Controlled Skeleton"><div className="p-3 space-y-2"><input className={input} value={title} onChange={e=>setTitle(e.target.value)} placeholder="Detection title"/><input className={input} value={ttp} onChange={e=>setTtp(e.target.value.toUpperCase())}/><select className={input} value={format} onChange={e=>setFormat(e.target.value)}>{['sigma','yara','kql','spl','eql'].map(v=><option key={v}>{v}</option>)}</select><button className="primary" disabled={!title||!ttp} onClick={()=>generate.mutate()}>Generate</button></div>{data.map(row=><button key={row.id} className="result" onClick={()=>setActive(row)}><b>{row.title}</b><small>{row.technique_id} · {row.format} · {row.created_by}</small></button>)}</Panel>
    </div>
    {active?<Panel title={`${active.title} · ${active.format.toUpperCase()}`}><textarea className={`${input} h-[520px] font-mono rounded-none border-0`} value={active.content} onChange={e=>setActive({...active,content:e.target.value})}/><div className="p-3 flex flex-wrap items-center gap-3"><button className="primary" onClick={()=>validate.mutate()}>Validate</button><span className={active.validation.valid?'text-green-400 text-xs':'text-amber-400 text-xs'}>{active.validation.valid?'Structurally valid':'Needs review'} · {active.validation.warnings.length} warnings · {active.validation.errors.length} errors</span>{typeof active.validation.source_url==='string'&&<a href={active.validation.source_url} target="_blank" rel="noreferrer" className="secondary">Source rule ↗</a>}</div></Panel>:<Empty text="Generate, sync, or select a detection rule. Imported Sigma/YARA rules retain source links and ATT&CK tags when available."/>}
  </div>;
}

function Imports(){
  const[kind,setKind]=useState<'stix'|'misp'|'atlas'>('stix');const[text,setText]=useState('{\n  \n}');const[result,setResult]=useState('');const run=useMutation({mutationFn:()=>pipelineApi.importJson(kind,JSON.parse(text)),onSuccess:data=>setResult(JSON.stringify(data,null,2)),onError:error=>setResult(String(error))});
  return <div className="max-w-5xl mx-auto"><Panel title="Reviewed Structured Import"><div className="p-3 space-y-3"><p className="text-xs text-gray-500">Paste a STIX bundle exported from TAXII, a MISP event, or MITRE ATLAS data. Imported reports enter pending intake.</p><select className={input} value={kind} onChange={e=>setKind(e.target.value as typeof kind)}><option value="stix">STIX / TAXII</option><option value="misp">MISP Event</option><option value="atlas">MITRE ATLAS</option></select><textarea className={`${input} h-72 font-mono`} value={text} onChange={e=>setText(e.target.value)}/><button className="primary" onClick={()=>run.mutate()}>Import and review</button>{result&&<pre className="p-3 bg-gray-950 text-xs text-gray-400 overflow-auto">{result}</pre>}</div></Panel></div>;
}

function Audit(){const{data=[]}=useQuery({queryKey:['pipeline-audit'],queryFn:pipelineApi.audit});return <div className="max-w-6xl mx-auto"><Panel title="Team Audit Trail">{data.map(row=><div key={row.id} className="grid md:grid-cols-[160px_180px_1fr] gap-3 p-3 border-b border-gray-800 text-xs"><span className="text-gray-600">{new Date(row.created_at).toLocaleString()}</span><span className="text-mitre-accent">{row.actor} · {row.action}</span><span className="text-gray-500">{row.object_type} {row.object_id}</span></div>)}</Panel></div>}
function Panel({title,children}:{title:string;children:React.ReactNode}){return <section className="rounded-lg border border-gray-800 bg-gray-900/60 overflow-hidden"><h2 className="text-sm font-semibold text-white px-3 py-3 border-b border-gray-800">{title}</h2>{children}</section>}
function Empty({text}:{text:string}){return <div className="rounded border border-gray-800 p-10 text-center text-sm text-gray-600">{text}</div>}
