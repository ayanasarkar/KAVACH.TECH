// Console menu: jump between the six workspaces, go back to the landing page, open the sample report.
// Workspaces are switched by clicking the real tab buttons, so this never touches app.js state.
import { initMenu } from './menu.js';

const tab = (i) => () => { const b = document.querySelectorAll('#ws button')[i]; if (b) b.click(); };
const W = [
  ['scope', ['Deny by default. Targets, exclusions, ports and tool policy.', 'The guard dry run shows what would be allowed or refused', 'before anything is launched.']],
  ['plan', ['What the agent proposes, with a reason for every step.', 'Nothing runs until you approve the plan.']],
  ['findings', ['Consolidated findings ranked by risk. Open one to see its', 'evidence, the tool that saw it and the confidence.']],
  ['approvals', ['Gated actions (a Metasploit check, for example) wait here.', 'Each one needs the tool, a reason and the target retyped.']],
  ['audit', ['The hash-chained log of every decision and run.', 'Verify it here, and download it.']],
  ['tools', ['Which adapters are live, import-only or approval-gated,', 'and which are installed on this machine.']],
];
const items = [
  { label: 'Chat console', href: '/console' },
  { label: 'Landing page', href: '/' },
  ...W.map(([k], i) => ({ label: (i + 1) + ':' + k, run: tab(i) })),
  { label: 'Sample report (PDF)', href: 'sample/sample-vapt-report.pdf' },
  { label: 'Keyboard shortcuts', run: () => document.dispatchEvent(new KeyboardEvent('keydown', { key: '?', bubbles: true })) },
];
const text = [
  ['The chat-first console: talk to the agent, approve plans,', 'open the proof for any finding.'],
  ['KAVACH', 'Back to the landing page.', '', 'It replays a recorded sample run.'],
  ...W.map(([, d]) => d),
  ['The report generated from the recorded sample run.', 'To get one for your own run, use the pdf command', 'at the prompt once an assessment has finished.'],
  ['One screen of keys: workspaces 1-6, / for the prompt,', 'j and k to move, a to approve the plan.'],
];
initMenu({
  button: document.getElementById('menu'),
  items,
  preview: (it, i) => text[i] || [],
  sideTitle: 'sample run · recorded audit block',
  footer: [{ kbd: 'm' }, ' toggle  ', { kbd: '↑' }, { kbd: '↓' }, ' move  ', { kbd: '1' }, '–', { kbd: '9' }, ' jump  ', { kbd: 'esc' }, ' close'],
});
