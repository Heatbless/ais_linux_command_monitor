const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const sourcePath = path.join(__dirname, '../ais/server/static/dashboard.js');
const {classifyEvent, scoreText, eventTime} = require(sourcePath);

const base = {host:'vm-01', account:'web', program:'nginx', source:'exec', status:'scored',
  ais:{score:0, threshold:0.5, alert:false}, markov:null, warnings:[]};

test('zero is a real score; an explicit negative decision is not flagged', () => {
  assert.equal(classifyEvent(base).kind, 'clear');
  assert.equal(scoreText(base.ais), '0 / 0.5');
});
test('warmup, missing profiles and missing decisions are not labelled normal', () => {
  for (const status of ['warming_up', 'no_profile', 'missing_session_context', 'missing_features']) {
    const result = classifyEvent({...base, status, ais:null});
    assert.equal(result.kind, 'unassessed'); assert.equal(result.flagged, false);
  }
  assert.equal(classifyEvent({...base, ais:{score:9, threshold:1, alert:null}}).kind, 'unassessed');
  assert.equal(scoreText({score:null, threshold:1}), 'Not assessed');
});
test('score magnitude alone never invents an alert decision', () => {
  assert.equal(classifyEvent({...base, ais:{score:99, threshold:1, alert:false}}).flagged, false);
  assert.equal(classifyEvent({...base, ais:{score:0, threshold:1, alert:true}}).kind, 'ais');
});
test('policy warnings highlight even an unassessed observation', () => {
  const result = classifyEvent({...base, status:'warming_up', ais:null,
    warnings:[{source:'rule', severity:'medium', reason:'Python policy review'}]});
  assert.equal(result.kind, 'medium'); assert.equal(result.flagged, true);
  assert.match(result.reasons[0], /^Policy:/);
});
test('highest warning severity is retained', () => {
  const result = classifyEvent({...base, warnings:[
    {source:'rule', severity:'low', reason:'Low'}, {source:'ais', severity:'critical', reason:'Critical'}]});
  assert.equal(result.kind, 'critical');
});
test('Markov flag is separate from the AIS decision', () => {
  const result = classifyEvent({...base, markov:{score:0.9, threshold:0.8, alert:true}});
  assert.equal(result.kind, 'comparison'); assert.equal(result.flagged, true);
  assert.match(result.reasons[0], /separate from the AIS/);
});
test('failed execution is an operational flag, not an attack verdict', () => {
  const result = classifyEvent({...base, status:'failed_execution', ais:null});
  assert.equal(result.kind, 'execution');
  assert.match(result.reasons[0], /not evidence of an attack/);
});
test('unknown observed time uses receipt time without inventing an epoch timestamp', () => {
  assert.match(eventTime({body:{timestamp:null}, received_at:1700000000}), /\(received\)$/);
  assert.equal(eventTime({body:{timestamp:null}, received_at:null}), 'Unknown');
  assert.doesNotMatch(eventTime({body:{timestamp:0}, received_at:1700000000}), /received/);
});

function browser() {
  class Element {
    constructor(tag) {this.tagName=tag; this.children=[]; this.textContent=''; this.checked=false; this.hidden=false;}
    append(...children) {
      for (const child of children) this.children.push(...(child.tagName === '#fragment' ? child.children : [child]));
    }
    replaceChildren(...children) {this.children=[]; this.append(...children);}
    set innerHTML(value) {throw new Error('Untrusted content must not be inserted as HTML');}
  }
  const ids = ['login','secret','stale','agents','alerts','events','more','flagged-only','log-count','log-empty'];
  const elements = Object.fromEntries(ids.map(id => [id,new Element(id === 'events' ? 'tbody' : 'div')]));
  const context = vm.createContext({document:{getElementById:id=>elements[id],
    createElement:tag=>new Element(tag), createDocumentFragment:()=>new Element('#fragment')},
    fetch:()=>Promise.reject(new Error('No test session')), setInterval:()=>{}, Date});
  // Expose block-scoped UI functions only within this test copy of the script.
  const instrumented = fs.readFileSync(sourcePath,'utf8').replace(/}\s*$/, 'globalThis.ui = {renderEvents};\n}');
  vm.runInContext(instrumented,context);
  const row = (id, body=base) => ({id, received_at:id, body});
  return {elements, ui:context.ui, row};
}
function plainText(node) {return node.textContent + node.children.map(plainText).join(' ');}

test('table rows, flag filtering and empty states use real event decisions', () => {
  const {elements,ui,row} = browser();
  ui.renderEvents({items:[row(3), row(2,{...base,ais:{...base.ais,alert:true}}),
    row(1,{...base,status:'warming_up',ais:null})],next_cursor:'1,1'});
  assert.equal(elements.events.children.length,3);
  assert.ok(elements.events.children.every(node=>node.tagName==='tr' && node.children.length===7));
  elements['flagged-only'].checked=true; elements['flagged-only'].onchange();
  assert.equal(elements.events.children.length,1);
  assert.equal(elements.events.children[0].className,'event-ais');
  ui.renderEvents({items:[row(4)],next_cursor:null});
  assert.equal(elements.events.children.length,0);
  assert.equal(elements['log-empty'].hidden,false);
  assert.match(elements['log-empty'].textContent,/No flagged rows/);
});
test('event content remains text; it cannot create HTML or executable nodes', () => {
  const {elements,ui,row} = browser();
  const payload='<img src=x onerror=alert(1)>';
  ui.renderEvents({items:[row(1,{...base,program:payload,warnings:[{source:'rule',severity:'high',reason:payload}]})],next_cursor:null});
  assert.ok(plainText(elements.events).includes(payload));
  function tags(node) {return [node.tagName,...node.children.flatMap(tags)];}
  assert.ok(!tags(elements.events).some(tag=>['img','script','iframe'].includes(tag)));
});
test('older pages survive a fresh latest-page update without duplicate rows', () => {
  const {elements,ui,row} = browser();
  ui.renderEvents({items:[row(3),row(2)],next_cursor:'2,2'});
  ui.renderEvents({items:[row(1)],next_cursor:null},true);
  ui.renderEvents({items:[row(4),row(3)],next_cursor:'3,3'});
  assert.equal(elements.events.children.length,4);
  assert.equal(elements.more.hidden,true);
});
