import { useState } from 'react';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { operationsApi, type DetectionCandidate, type IntakeRecord, type Investigation } from '@/api/client';
import { Header } from '@/components/Layout/Header';
import { PermissionNotice } from '@/components/PermissionNotice';
import { useHasPermission } from '@/hooks/useCurrentUser';
import { useAppStore } from '@/store';

type Tab = 'investigations' | 'intake' | 'detections' | 'tracking';
const input = 'w-full bg-gray-800 border border-gray-700 rounded px-3 py-2 text-xs text-gray-200 outline-none focus:border-mitre-accent';

export function Operations() {
  const [tab, setTab] = useState<Tab>('investigations');
  return <div className="flex flex-col h-full"><Header title="Operational Intelligence" />
    <div className="flex gap-5 px-6 border-b border-gray-700">{(['investigations','intake','detections','tracking'] as Tab[]).map(item => <button key={item} onClick={() => setTab(item)} className={`py-3 capitalize text-sm border-b-2 ${tab === item ? 'border-mitre-accent text-white' : 'border-transparent text-gray-500'}`}>{item}</button>)}</div>
    <div className="flex-1 overflow-y-auto p-6">{tab === 'investigations' && <Investigations />}{tab === 'intake' && <Intake />}{tab === 'detections' && <Detections />}{tab === 'tracking' && <Tracking />}</div>
  </div>;
}

function Investigations() {
  const canManage = useHasPermission('manage_intel');
  const qc = useQueryClient(); const { domain, selectedTechniques, overlayGroupId } = useAppStore();
  const { data = [] } = useQuery({ queryKey: ['operations-investigations'], queryFn: operationsApi.investigations });
  const [active, setActive] = useState<Investigation | null>(null); const [name, setName] = useState('');
  const create = useMutation({ mutationFn: () => operationsApi.createInvestigation({ name, description: '', status: 'active', domain, actor_ids: overlayGroupId ? [overlayGroupId] : [], technique_ids: [...selectedTechniques], report_ids: [], evidence_nodes: [], evidence_edges: [], timeline: [{ at: new Date().toISOString(), event: 'Investigation created' }] }), onSuccess: row => { setActive(row); setName(''); qc.invalidateQueries({ queryKey: ['operations-investigations'] }); } });
  const save = useMutation({ mutationFn: (row: Investigation) => operationsApi.updateInvestigation(row.id, strip(row)), onSuccess: row => { setActive(row); qc.invalidateQueries({ queryKey: ['operations-investigations'] }); } });
  return <div className="grid lg:grid-cols-[320px_1fr] gap-5 max-w-7xl mx-auto">
    <Panel title="Campaign / Investigation Workspaces">{canManage ? <div className="flex gap-2 p-2"><input value={name} onChange={e => setName(e.target.value)} placeholder="New investigation name" className={input}/><button onClick={() => create.mutate()} disabled={!name.trim()} className="primary">Create</button></div> : <div className="p-3"><PermissionNotice permission="manage_intel" action="create or change investigations" compact /></div>}{data.map(row => <button key={row.id} onClick={() => setActive(row)} className="result"><b>{row.name}</b><small>{row.status} · {row.technique_ids.length} TTPs · {row.actor_ids.length} actors</small></button>)}</Panel>
    {active ? <Panel title={active.name}><fieldset disabled={!canManage} className="grid md:grid-cols-2 gap-3 p-3 disabled:opacity-70">
      <Field label="Status"><select value={active.status} onChange={e => setActive({...active,status:e.target.value})} className={input}>{['active','monitoring','review','closed'].map(v => <option key={v}>{v}</option>)}</select></Field>
      <Field label="Description"><textarea value={active.description} onChange={e => setActive({...active,description:e.target.value})} className={input}/></Field>
      <Field label="Actors"><Csv value={active.actor_ids} onChange={actor_ids => setActive({...active,actor_ids})}/></Field>
      <Field label="Techniques"><Csv value={active.technique_ids} onChange={technique_ids => setActive({...active,technique_ids})}/></Field>
      <Field label="Evidence nodes"><JsonEditor value={active.evidence_nodes} onChange={evidence_nodes => setActive({...active,evidence_nodes})}/></Field>
      <Field label="Evidence relationships"><JsonEditor value={active.evidence_edges} onChange={evidence_edges => setActive({...active,evidence_edges})}/></Field>
      <Field label="Timeline"><JsonEditor value={active.timeline} onChange={timeline => setActive({...active,timeline})}/></Field>
    </fieldset>{canManage && <div className="p-3"><button onClick={() => save.mutate(active)} className="primary">Save investigation</button></div>}</Panel> : <Empty text="Select or create an investigation. New investigations inherit the current actor overlay and selected TTPs." />}
  </div>;
}

function Intake() {
  const canManage = useHasPermission('manage_intel');
  const qc = useQueryClient(); const { data = [] } = useQuery({ queryKey: ['operations-intake'], queryFn: operationsApi.intake }); const [title,setTitle]=useState(''); const [url,setUrl]=useState('');
  const create = useMutation({ mutationFn: () => operationsApi.createIntake({ title,url,publisher:'',status:'pending',summary:'',source_reliability:'unknown',actor_ids:[],technique_ids:[],indicators:[],analyst_notes:'' }), onSuccess: () => { setTitle(''); setUrl(''); qc.invalidateQueries({queryKey:['operations-intake']}); } });
  const update = useMutation({ mutationFn: (row: IntakeRecord) => operationsApi.updateIntake(row.id, strip(row)), onSuccess: () => qc.invalidateQueries({queryKey:['operations-intake']}) });
  return <div className="max-w-6xl mx-auto space-y-4"><Panel title="Report Intake And Analyst Review">{canManage ? <div className="grid md:grid-cols-[1fr_1fr_auto] gap-2 p-3"><input value={title} onChange={e=>setTitle(e.target.value)} placeholder="Report title" className={input}/><input value={url} onChange={e=>setUrl(e.target.value)} placeholder="Source URL" className={input}/><button onClick={()=>create.mutate()} disabled={!title.trim()} className="primary">Add</button></div> : <div className="p-3"><PermissionNotice permission="manage_intel" action="add or review report intake records" compact /></div>}</Panel><div className="grid lg:grid-cols-2 gap-3">{data.map(row => <Panel key={row.id} title={row.title}><p className="text-xs text-gray-500 px-3">{row.url || 'No URL'} · {row.publisher || 'Publisher pending'}</p><div className="flex gap-2 p-3"><select disabled={!canManage} value={row.status} onChange={e=>update.mutate({...row,status:e.target.value})} className={input}>{['pending','reviewing','promoted','rejected'].map(v=><option key={v}>{v}</option>)}</select><select disabled={!canManage} value={row.source_reliability} onChange={e=>update.mutate({...row,source_reliability:e.target.value})} className={input}>{['unknown','A1','B1','B2','C2','D3'].map(v=><option key={v}>{v}</option>)}</select></div></Panel>)}</div></div>;
}

function Detections() {
  const canManage = useHasPermission('manage_detections');
  const qc=useQueryClient(); const {selectedTechniques}=useAppStore(); const {data=[]}=useQuery({queryKey:['operations-detections'],queryFn:operationsApi.detections}); const [title,setTitle]=useState(''); const [ttp,setTtp]=useState([...selectedTechniques][0]??'');
  const create=useMutation({mutationFn:()=>operationsApi.createDetection({title,technique_id:ttp,status:'idea',owner:'',telemetry:[],query_language:'',query:'',validation_notes:'',source_refs:[]}),onSuccess:()=>{setTitle('');qc.invalidateQueries({queryKey:['operations-detections']})}});
  const update=useMutation({mutationFn:(row:DetectionCandidate)=>operationsApi.updateDetection(row.id,strip(row)),onSuccess:()=>qc.invalidateQueries({queryKey:['operations-detections']})});
  return <div className="max-w-7xl mx-auto"><Panel title="Detection Engineering Lifecycle">{canManage ? <div className="grid md:grid-cols-[1fr_180px_auto] gap-2 p-3"><input value={title} onChange={e=>setTitle(e.target.value)} placeholder="Detection candidate title" className={input}/><input value={ttp} onChange={e=>setTtp(e.target.value.toUpperCase())} placeholder="T1059.001" className={input}/><button onClick={()=>create.mutate()} disabled={!title||!ttp} className="primary">Create</button></div> : <div className="p-3"><PermissionNotice permission="manage_detections" action="create or change detection candidates" compact /></div>}</Panel><div className="grid lg:grid-cols-3 gap-3 mt-4">{data.map(row=><Panel key={row.id} title={row.title}><p className="px-3 text-xs font-mono text-mitre-accent">{row.technique_id}</p><fieldset disabled={!canManage} className="p-3 space-y-2 disabled:opacity-70"><select value={row.status} onChange={e=>update.mutate({...row,status:e.target.value})} className={input}>{['idea','hunt','draft','validation','production','retired'].map(v=><option key={v}>{v}</option>)}</select><input value={row.owner} onChange={e=>update.mutate({...row,owner:e.target.value})} placeholder="Owner" className={input}/><textarea value={row.validation_notes} onChange={e=>update.mutate({...row,validation_notes:e.target.value})} placeholder="Validation results / false positives" className={input}/></fieldset></Panel>)}</div></div>;
}

function Tracking() {
  const canManage = useHasPermission('manage_intel');
  const qc=useQueryClient(); const {data=[]}=useQuery({queryKey:['operations-tracking'],queryFn:operationsApi.trackedActors}); const [id,setId]=useState(''); const [name,setName]=useState(''); const [techs,setTechs]=useState('');
  const track=useMutation({mutationFn:()=>operationsApi.trackActor({actor_id:id,actor_name:name,snapshot:{technique_ids:techs.split(',').map(v=>v.trim()).filter(Boolean)}}),onSuccess:()=>qc.invalidateQueries({queryKey:['operations-tracking']})});
  return <div className="max-w-6xl mx-auto"><Panel title="Tracked Actor Change Monitoring">{canManage ? <div className="grid md:grid-cols-[140px_1fr_1fr_auto] gap-2 p-3"><input value={id} onChange={e=>setId(e.target.value.toUpperCase())} placeholder="G0069" className={input}/><input value={name} onChange={e=>setName(e.target.value)} placeholder="Actor name" className={input}/><input value={techs} onChange={e=>setTechs(e.target.value)} placeholder="T1059.001, T1105" className={input}/><button onClick={()=>track.mutate()} disabled={!id} className="primary">Snapshot</button></div> : <div className="p-3"><PermissionNotice permission="manage_intel" action="create actor monitoring snapshots" compact /></div>}</Panel><div className="grid lg:grid-cols-2 gap-3 mt-4">{data.map(row=><Panel key={row.id} title={`${row.actor_name || row.actor_id} (${row.actor_id})`}><p className="px-3 text-xs text-gray-500">{(row.last_snapshot.technique_ids as string[] ?? []).length} techniques · {row.change_log.length} recorded changes</p><pre className="m-3 p-2 rounded bg-gray-950 text-[10px] text-gray-500 overflow-auto max-h-40">{JSON.stringify(row.change_log.slice(0,5),null,2)}</pre></Panel>)}</div></div>;
}

function strip<T extends {id:string;created_at:string;updated_at:string}>(row:T): Omit<T,'id'|'created_at'|'updated_at'>{const {id:_id,created_at:_created,updated_at:_updated,...rest}=row;return rest;}
function Panel({title,children}:{title:string;children:React.ReactNode}){return <section className="rounded-lg border border-gray-800 bg-gray-900/60 overflow-hidden"><h2 className="text-sm font-semibold text-white px-3 py-3 border-b border-gray-800">{title}</h2>{children}</section>}
function Field({label,children}:{label:string;children:React.ReactNode}){return <label className="text-[10px] uppercase tracking-wide text-gray-500">{label}<div className="mt-1">{children}</div></label>}
function Csv({value,onChange}:{value:string[];onChange:(v:string[])=>void}){return <input value={value.join(', ')} onChange={e=>onChange(e.target.value.split(',').map(v=>v.trim()).filter(Boolean))} className={input}/>}
function JsonEditor({value,onChange}:{value:Array<Record<string,unknown>>;onChange:(v:Array<Record<string,unknown>>)=>void}){return <textarea defaultValue={JSON.stringify(value,null,2)} onBlur={e=>{try{onChange(JSON.parse(e.target.value))}catch{}}} className={`${input} h-32 font-mono`}/>}
function Empty({text}:{text:string}){return <div className="rounded border border-gray-800 p-10 text-center text-sm text-gray-600">{text}</div>}
