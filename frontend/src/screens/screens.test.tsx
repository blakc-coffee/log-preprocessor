import { describe, expect, it } from 'vitest';
import { screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { http, HttpResponse } from 'msw';
import { renderAt } from '../test/render';
import { g, server } from '../test/server';

const PA_YAML = `id: palo_alto_traffic
version: 1.0.0
extractors:
  - id: pan_traffic
    kind: csv
    columns: [_, ts, _, _, _, _, _, src_ip, dst_ip]
    map:
      - {from: src_ip, to: src_endpoint.ip, type: ip}
      - {from: dst_ip, to: dst_endpoint.ip, type: ip}
`;

const footer = () => screen.getByRole('group', { name: /verification/i });

describe('Lineage Explorer', () => {
  it('lists events in the unified schema with telemetry', async () => {
    renderAt('/');
    expect(await screen.findByText(/5 loaded of 8 events/)).toBeInTheDocument();
    const rows = screen.getByRole('rowgroup', { name: 'Event rows' });
    expect(within(rows).getAllByText('Cisco ASA')).toHaveLength(3);
    expect(within(rows).getByText('Fortinet')).toBeInTheDocument();
    expect(within(rows).getByText('Suricata')).toBeInTheDocument();
    expect(within(rows).getByText('carol · laptop-carol')).toBeInTheDocument(); // resolved identity
    expect(await screen.findByText('812')).toBeInTheDocument(); // eps_1m 812.4 in the telemetry golden, rounded above 100
  });

  it('shows the admin banner and keeps the SPA when the admin is down', async () => {
    server.use(http.get('*/healthz', () => HttpResponse.json({ status: 'ok', admin: 'unreachable' })));
    renderAt('/');
    expect(await screen.findByRole('alert')).toHaveTextContent(/admin API is not answering/);
    expect(screen.getByRole('heading', { name: 'Unified Lineage Explorer' })).toBeInTheDocument();
  });

  it('turns the search box into admin filters', async () => {
    let seen = '';
    server.use(
      http.get('*/api/events', ({ request }) => {
        seen = new URL(request.url).search;
        return HttpResponse.json({ events: [], next_cursor: null, max_seq: 0 });
      }),
    );
    renderAt('/');
    await userEvent.type(screen.getByRole('searchbox', { name: 'Search events' }), '10.1.4.7 user:alice');
    await waitFor(() => expect(seen).toContain('ip=10.1.4.7'));
    expect(seen).toContain('user=alice');
    expect(await screen.findByText('No events match these filters.')).toBeInTheDocument();
  });
});

describe('Forensic split modal: verification in the browser', () => {
  const id = encodeURIComponent(g.sealed.event_id);

  it('passes all three checks for the golden sealed event', async () => {
    renderAt(`/events/${id}`);
    const f = footer();
    await waitFor(() => expect(within(f).getAllByText('PASSED')).toHaveLength(3));
    expect(f).toHaveTextContent(/Leaf 1 of 8 in segment 1; chain link verified/);
    expect(screen.getByRole('region', { name: 'Hex dump' })).toHaveTextContent('3c 31 36 36'); // "<166"
  });

  it('fails SHA-256 and Merkle when one raw byte is altered', async () => {
    const bytes = Uint8Array.from(atob(g.raw.raw_base64), (c) => c.charCodeAt(0));
    bytes[20]! ^= 1;
    server.use(
      http.get('*/api/events/:id/raw', () =>
        HttpResponse.json({ ...g.raw, raw_base64: btoa(String.fromCharCode(...bytes)) }),
      ),
    );
    renderAt(`/events/${id}`);
    const f = footer();
    await waitFor(() => expect(within(f).getAllByText('FAILED')).toHaveLength(2));
    expect(f).toHaveTextContent(/hash to/);
  });

  it('never trusts the server: a lying sha_match does not help', async () => {
    const bytes = Uint8Array.from(atob(g.raw.raw_base64), (c) => c.charCodeAt(0));
    bytes[0]! ^= 1;
    server.use(
      http.get('*/api/events/:id/raw', () =>
        HttpResponse.json({ ...g.raw, sha_match: true, raw_base64: btoa(String.fromCharCode(...bytes)) }),
      ),
    );
    renderAt(`/events/${id}`);
    await waitFor(() => expect(within(footer()).getAllByText('FAILED').length).toBeGreaterThan(0));
  });

  it('reports an unsealed segment as pending, not failed', async () => {
    renderAt(`/events/${encodeURIComponent(g.events[1]!.event_id)}`);
    const f = footer();
    await waitFor(() => expect(f).toHaveTextContent('Segment not sealed yet, proof available after seal.'));
    expect(within(f).getByText('PENDING')).toBeInTheDocument();
  });

  it('closes on Escape', async () => {
    renderAt(`/events/${id}`);
    await screen.findByRole('dialog');
    await userEvent.keyboard('{Escape}');
    await waitFor(() => expect(screen.queryByRole('dialog')).not.toBeInTheDocument());
  });
});

describe('Review Queue', () => {
  const open = async () => {
    renderAt('/review/proposal/prop-01');
    return await screen.findByRole('button', { name: 'Approve & Replay from Vault' });
  };

  it('needs a recorded name, then approves and shows the replay', async () => {
    let body: Record<string, unknown> = {};
    server.use(
      http.post('*/api/proposals/:id/approve', async ({ request }) => {
        body = (await request.json()) as Record<string, unknown>;
        return HttpResponse.json({ parser_id: 'palo_alto_traffic', version: '1.0.0', replay_job_id: 'replay-01' });
      }),
    );
    const approve = await open();
    expect(approve).toBeDisabled();
    await userEvent.type(screen.getByRole('textbox', { name: 'Recorded name' }), 'Nisha');
    expect(approve).toBeEnabled();
    await userEvent.click(approve);
    expect(await screen.findByRole('button', { name: /View 50 recovered events/ })).toBeInTheDocument();
    expect(body).toMatchObject({ approved_by: 'Nisha' });
    expect(body.yaml).toBeUndefined(); // unedited: the server uses the proposal's own YAML
    expect(localStorage.getItem('ulpf.recordedName')).toBe('Nisha');
  });

  it('asks for "approve anyway" when the dry run misses the thresholds', async () => {
    server.use(
      http.get('*/api/proposals/:id', () =>
        HttpResponse.json({
          proposal: { ...g.proposal, dry_run: { ...g.proposal.dry_run!, match_rate: 0.5 } },
          active_yaml: '',
        }),
      ),
    );
    server.use(
      http.get('*/api/proposals', () =>
        HttpResponse.json({ proposals: [{ ...g.proposal, dry_run: { ...g.proposal.dry_run!, match_rate: 0.5 } }] }),
      ),
    );
    const approve = await open();
    await userEvent.type(screen.getByRole('textbox', { name: 'Recorded name' }), 'Nisha');
    await userEvent.click(approve);
    expect(await screen.findByText(/below the acceptance thresholds/)).toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Approve anyway' })).toBeInTheDocument();
  });

  it('explains a stale base version', async () => {
    server.use(
      http.post('*/api/proposals/:id/approve', () =>
        HttpResponse.json({ error: { code: 'stale_base_version', message: 'base changed' } }, { status: 409 }),
      ),
    );
    const approve = await open();
    await userEvent.type(screen.getByRole('textbox', { name: 'Recorded name' }), 'Nisha');
    await userEvent.click(approve);
    expect(await screen.findByText(/Base version changed/i)).toBeInTheDocument();
    expect(screen.queryByRole('button', { name: 'Approve & Replay from Vault' })).not.toBeInTheDocument();
  });

  it('marks low-confidence fields and edits the YAML from the table', async () => {
    server.use(
      http.get('*/api/proposals/:id', () =>
        HttpResponse.json({ proposal: { ...g.proposal, yaml: PA_YAML }, active_yaml: '' }),
      ),
    );
    server.use(http.get('*/api/proposals', () => HttpResponse.json({ proposals: [{ ...g.proposal, yaml: PA_YAML }] })));
    await open();
    // The golden's col_8 has confidence 0.88 but an alternative; col_7 is 0.91: neither is marked.
    expect(screen.queryByRole('combobox', { name: 'OCSF path for col_7' })).not.toBeInTheDocument();
    await userEvent.click(screen.getByRole('tab', { name: /Parser YAML/ }));
    expect(screen.getByText('- {from: src_ip, to: src_endpoint.ip, type: ip}')).toBeInTheDocument();
    expect(screen.getByRole('tab', { name: 'Parser YAML' })).toBeInTheDocument();
  });

  it('maps an abstained column from the table, rewrites one YAML line and marks the dry run stale', async () => {
    const yaml = PA_YAML.replace(
      'columns: [_, ts, _, _, _, _, _, src_ip, dst_ip]',
      'columns: [_, ts, _, _, _, _, _, src_ip, dst_ip, _, _, _, _]',
    );
    const p = {
      ...g.proposal,
      yaml,
      typed_fields: [
        ...g.proposal.typed_fields,
        { field: 'col_12', ocsf_path: '', type: 'username', confidence: 0.41, evidence: 'word-like' },
      ],
    };
    server.use(http.get('*/api/proposals/:id', () => HttpResponse.json({ proposal: p, active_yaml: '' })));
    server.use(http.get('*/api/proposals', () => HttpResponse.json({ proposals: [p] })));
    await open();
    await userEvent.selectOptions(screen.getByRole('combobox', { name: 'OCSF path for col_12' }), 'actor.user.name');
    expect(screen.getByRole('tab', { name: 'Parser YAML · edited' })).toBeInTheDocument();
    expect(screen.getByText(/The YAML changed since the last dry run/)).toBeInTheDocument();
    await userEvent.click(screen.getByRole('tab', { name: 'Parser YAML · edited' }));
    await userEvent.click(screen.getByRole('button', { name: 'Diff vs proposed' }));
    expect(screen.getByText('3 changed lines')).toBeInTheDocument(); // columns line out, in; one map line added
    expect(screen.getByText('- {from: col_12, to: actor.user.name, type: string}')).toBeInTheDocument();
  });

  it('lists drift alerts and quarantine clusters alongside proposals', async () => {
    renderAt('/review/proposal/prop-01');
    expect(await screen.findByText(g.drift.signals[0]!)).toBeInTheDocument();
    expect(screen.getByText('Extractor failed')).toBeInTheDocument();
  });
});
