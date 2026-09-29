// msw handlers serving the contract's golden files, so component tests run
// against the exact payload shapes the admin API promises.
import { http, HttpResponse } from 'msw';
import { setupServer } from 'msw/node';
import { golden } from './repo';
import type {
  DriftAlert,
  Lineage,
  NormalizedEvent,
  Proposal,
  QuarantineList,
  RawResponse,
  ReplayJob,
  Telemetry,
} from '../api/types';

export const g = {
  events: ['event_asa_built', 'event_asa_deny', 'event_fortinet', 'event_suricata_alert', 'event_with_entities'].map(
    (n) => golden<NormalizedEvent>(n),
  ),
  raw: golden<RawResponse>('raw_response'),
  sealed: golden<Lineage>('lineage_sealed'),
  pending: golden<Lineage>('lineage_pending'),
  telemetry: golden<Telemetry>('telemetry'),
  proposal: golden<Proposal>('proposal_palo_alto'),
  drift: golden<DriftAlert>('drift_alert'),
  quarantine: golden<QuarantineList>('quarantine_list'),
  replay: golden<ReplayJob>('replay_job'),
};

export const handlers = [
  http.get('*/healthz', () => HttpResponse.json({ status: 'ok', admin: 'reachable' })),
  http.get('*/api/telemetry', () => HttpResponse.json(g.telemetry)),
  http.get('*/api/events', ({ request }) => {
    const u = new URL(request.url);
    if (u.searchParams.has('since_seq')) return HttpResponse.json({ events: [], next_cursor: null, max_seq: 10 });
    return HttpResponse.json({ events: g.events, next_cursor: null, max_seq: 10 });
  }),
  http.get('*/api/events/:id/raw', () => HttpResponse.json(g.raw)),
  http.get('*/api/events/:id', ({ params }) => {
    const e = g.events.find((x) => x.event_id === params.id);
    return e
      ? HttpResponse.json(e)
      : HttpResponse.json({ error: { code: 'not_found', message: 'no such event' } }, { status: 404 });
  }),
  http.get('*/api/lineage/:id', ({ params }) =>
    HttpResponse.json(params.id === g.sealed.event_id ? g.sealed : { ...g.pending, event_id: params.id }),
  ),
  http.get('*/api/proposals', () => HttpResponse.json({ proposals: [g.proposal] })),
  http.get('*/api/proposals/:id', () => HttpResponse.json({ proposal: g.proposal, active_yaml: '' })),
  http.get('*/api/drift', () => HttpResponse.json({ alerts: [g.drift] })),
  http.get('*/api/quarantine', () => HttpResponse.json(g.quarantine)),
  http.get('*/api/samples', () => HttpResponse.json({ samples: [] })),
  http.get('*/api/history', () => HttpResponse.json({ history: [] })),
  http.get('*/api/replay/:id', () => HttpResponse.json(g.replay)),
  http.post('*/api/proposals/:id/approve', () =>
    HttpResponse.json({ parser_id: 'palo_alto_traffic', version: '1.0.0', replay_job_id: 'replay-01' }),
  ),
];

export const server = setupServer(...handlers);
