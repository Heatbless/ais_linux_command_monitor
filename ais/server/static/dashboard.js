'use strict';

function classifyEvent(a) {
  const warnings = Array.isArray(a.warnings) ? a.warnings : [];
  const aisFlag = a.ais?.alert === true;
  const markovFlag = a.markov?.alert === true;
  const reasons = warnings.map(w => `${w.source === 'rule' ? 'Policy' : 'AIS warning'}: ${w.reason}`);
  if (aisFlag) reasons.push('AIS detector explicitly flagged this observation.');
  if (markovFlag) reasons.push('Markov comparison flagged this observation; this is separate from the AIS decision.');
  if (a.status === 'failed_execution') reasons.push('Execution failed; this alone is not evidence of an attack.');
  if (warnings.length) {
    const severity = ['critical', 'high', 'medium', 'low'].find(level => warnings.some(w => w.severity === level)) || 'low';
    return {flagged:true, kind:severity, label:`${severity.toUpperCase()} warning${aisFlag ? ' + AIS flag' : ''}`, reasons};
  }
  if (aisFlag) return {flagged:true, kind:'ais', label:'AIS flagged', reasons};
  if (a.status === 'failed_execution') return {flagged:true, kind:'execution', label:'Execution failed', reasons};
  if (markovFlag) return {flagged:true, kind:'comparison', label:'Markov comparison flagged', reasons};
  if (a.status === 'scored' && Number.isFinite(a.ais?.score) && a.ais?.alert === false) {
    return {flagged:false, kind:'clear', label:'Not flagged', reasons:['No AIS flag or policy warning reported.']};
  }
  return {flagged:false, kind:'unassessed', label:'Not assessed / no decision', reasons:[`Detector status: ${a.status || 'unavailable'}`]};
}
function scoreText(score) {
  if (!score || !Number.isFinite(score.score)) return 'Not assessed';
  return `${score.score} / ${Number.isFinite(score.threshold) ? score.threshold : '—'}`;
}
function eventTime(row) {
  const observed = Number.isFinite(row.body?.timestamp);
  const seconds = observed ? row.body.timestamp : row.received_at;
  if (!Number.isFinite(seconds)) return 'Unknown';
  const date = new Date(seconds * 1000);
  return Number.isNaN(date.getTime()) ? 'Unknown' : date.toLocaleString() + (observed ? '' : ' (received)');
}
if (typeof module !== 'undefined' && module.exports) module.exports = {classifyEvent, scoreText, eventTime};

if (typeof document !== 'undefined') {
let csrf = '', cursor = null, eventRows = [], olderLoaded = false;
const el = id => document.getElementById(id);
const text = (tag, value) => {const e = document.createElement(tag); e.textContent = value; return e;};
async function api(path, options={}) {const r=await fetch(path,options); if(!r.ok) throw new Error('Request failed ('+r.status+')'); return r.json();}
el('login').onsubmit = async e => { e.preventDefault(); try {const result=await api('/operator/login',{method:'POST',body:el('secret').value}); csrf=result.csrf; el('secret').value=''; el('login').hidden=true; await refresh();} catch(err) {el('stale').textContent=err.message;} };
function card(target, title, value) {const a=text('article',''); a.append(text('h3',title),text('p',value)); target.append(a); return a;}
function drawEvents() {
  const onlyFlagged = el('flagged-only').checked;
  const fragment = document.createDocumentFragment();
  let shown = 0;
  for (const row of eventRows) {
    const a = row.body, result = classifyEvent(a);
    if (onlyFlagged && !result.flagged) continue;
    shown++;
    const tr = document.createElement('tr'); tr.className = 'event-' + result.kind;
    tr.append(text('td', eventTime(row)), text('td', `${a.host} / ${a.account}`), text('td', `${a.program} · ${a.source}`));
    const state = document.createElement('td'), badge = text('span', result.label);
    badge.className = 'badge'; state.append(badge, text('small', a.status));
    tr.append(state, text('td', scoreText(a.ais)));
    const comparison = document.createElement('td'); comparison.append(text('span', scoreText(a.markov)));
    if (a.markov?.alert === true) comparison.append(text('small', 'Comparison flag'));
    tr.append(comparison);
    const reason = document.createElement('td');
    for (const message of result.reasons) reason.append(text('p', message));
    const details = document.createElement('details');
    details.append(text('summary', 'Sanitized event details'), text('pre', JSON.stringify(a, null, 2)));
    reason.append(details); tr.append(reason); fragment.append(tr);
  }
  el('events').replaceChildren(fragment);
  el('log-count').textContent = `${shown} shown · ${eventRows.length} loaded · ${eventRows.filter(row => classifyEvent(row.body).flagged).length} flagged`;
  el('log-empty').hidden = shown > 0;
  el('log-empty').textContent = eventRows.length && onlyFlagged ? 'No flagged rows in loaded activity. Load older activity to check earlier events.' : 'No activity received yet.';
  el('more').hidden = !cursor;
}
function renderEvents(data, append=false) {
  if (append) {
    const seen = new Set(eventRows.map(row => row.id));
    eventRows.push(...data.items.filter(row => !seen.has(row.id)));
    olderLoaded = true; cursor = data.next_cursor;
  } else if (olderLoaded) {
    const fresh = new Set(data.items.map(row => row.id));
    eventRows = [...data.items, ...eventRows.filter(row => !fresh.has(row.id))];
  } else {
    eventRows = data.items; cursor = data.next_cursor;
  }
  drawEvents();
}
el('flagged-only').onchange = drawEvents;
async function refresh() {try {const [agents,alerts,events]=await Promise.all([api('/api/v1/agents'),api('/api/v1/alerts'),api('/api/v1/events')]); el('agents').replaceChildren(); for(const a of agents.items) {const h=a.heartbeat; const node=card(el('agents'),a.name+' · '+a.state, a.host+' · '+(a.run ? a.run.mode.toUpperCase() : 'No run')+' · heartbeat '+(a.heartbeat_at===null?'never':Math.floor(agents.server_time-a.heartbeat_at)+'s ago')); if(h) node.append(text('p','Collector '+h.collector.state+' · delivery '+h.delivery.state+' · queued '+h.delivery.queue_depth+' / '+h.delivery.queue_bytes+' bytes · losses '+h.delivery.dropped_assessments+' assessments / '+h.delivery.dropped_warnings+' warnings · '+(h.detector.experimental?'EXPERIMENTAL MODEL':'Model metadata supplied'))); const button=text('button','Health and coverage'); button.onclick=async()=>{try{const detail=await api('/api/v1/agents/'+a.id); const pre=text('pre',JSON.stringify(detail,null,2)); node.append(pre); button.disabled=true;}catch(err){el('stale').textContent=err.message;}}; node.append(button); } el('alerts').replaceChildren(); for(const a of alerts.items){const w=a.body.warning; const node=card(el('alerts'),a.severity+' · '+a.rule+' · '+a.source, a.body.account+' / '+a.body.role+' · '+w.reason+' · count '+a.count+' · '+w.evidence_programs.join(' → ')+' · stages '+a.body.stage_hints.join(', ')); const b=text('button',a.acknowledged?'Acknowledged':'Acknowledge'); b.disabled=!!a.acknowledged; b.onclick=async()=>{try{await api('/api/v1/alerts/'+a.id+'/acknowledge',{method:'POST',headers:{'X-CSRF-Token':csrf}}); await refresh();}catch(err){el('stale').textContent=err.message;}}; node.append(b);} renderEvents(events); el('stale').textContent='Connected · updated '+new Date().toLocaleTimeString(); el('stale').className='connected';} catch(err){el('stale').textContent='Disconnected / stale data · '+err.message; el('stale').className='stale';}}
el('more').onclick=async()=>{try{renderEvents(await api('/api/v1/events?cursor='+encodeURIComponent(cursor)),true);}catch(err){el('stale').textContent='Disconnected / stale data · '+err.message;}};
api('/operator/session').then(session=>{csrf=session.csrf; el('login').hidden=true; return refresh();}).catch(()=>{}); setInterval(()=>{if(el('login').hidden) refresh();},5000);
}
