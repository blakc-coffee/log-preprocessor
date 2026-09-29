import { useMemo, useState } from 'react';
import { useQuery } from '@tanstack/react-query';
import { useTimeline } from '../api/hooks';
import { api } from '../api/client';
import type { Binding, EventList, NormalizedEvent } from '../api/types';
import { fmtClock, fmtDateTime, fmtInt, productName } from '../lib/format';
import { isIP } from '../lib/search';
import { useUtc } from '../components/utc';
import { Button, Card, cx, Empty, Input, Label, PageHeader, StatCard, Td, Th, Table, rowClass } from '../components/ui';

/**
 * Identity Timeline (PRD screen 4, not in the Figma set): built only from the
 * shared components. Bindings are lanes of lavender bars; gaps stay empty,
 * because the resolver never carries a user across a release.
 */
export default function Identity() {
  const utc = useUtc();
  const [input, setInput] = useState('10.1.4.7');
  const [ip, setIp] = useState('10.1.4.7');
  const tl = useTimeline(ip);
  const bindings = useMemo(() => tl.data?.bindings ?? [], [tl.data]);

  // The window is bounded by the data, not the wall clock: from just before
  // the first binding to the newest binding edge or event on this address.
  const start = bindings.length ? Math.min(...bindings.map((b) => Date.parse(b.valid_from))) - 5 * 60_000 : 0;
  const events = useQuery({
    queryKey: ['identityEvents', ip],
    queryFn: () => api.get<EventList>('/api/events', { ip, limit: 500 }),
    enabled: !!ip,
    refetchInterval: 5000,
  });
  const fw = useMemo(
    () =>
      (events.data?.events ?? [])
        .filter((e) => !e.identity)
        .slice()
        .reverse(),
    [events.data],
  );
  const until =
    Math.max(
      start + 60_000,
      ...bindings.map((b) => Date.parse(b.valid_to ?? b.valid_from)),
      ...fw.map((e) => Date.parse(e.event_time ?? e.received_at)),
    ) +
    2 * 60_000;

  const users = bindings.filter((b) => b.user);
  const reassignments = users.filter((b, i) => i > 0 && b.user !== users[i - 1]!.user).length;
  const gaps = users.filter(
    (b, i) => i > 0 && users[i - 1]!.valid_to && Date.parse(b.valid_from) > Date.parse(users[i - 1]!.valid_to!),
  ).length;

  return (
    <div className="flex-1 min-h-0 flex flex-col gap-4 py-6">
      <PageHeader title="Identity Timeline" subtitle="Who held an address, when, and on what evidence.">
        <form
          className="flex gap-2"
          onSubmit={(e) => {
            e.preventDefault();
            if (isIP(input.trim())) setIp(input.trim());
          }}
        >
          <Input
            aria-label="IP address"
            value={input}
            onChange={(e) => setInput(e.target.value)}
            placeholder="IP address"
            mono
            className="w-48"
          />
          <Button type="submit" disabled={!isIP(input.trim())}>
            Show
          </Button>
        </form>
      </PageHeader>
      <section aria-label="Identity summary" className="grid grid-cols-4 gap-4 shrink-0">
        <StatCard label="Bindings" value={fmtInt(bindings.length)} sub={ip} />
        <StatCard label="Users" value={fmtInt(new Set(users.map((b) => b.user)).size)} />
        <StatCard label="Reassignments" value={fmtInt(reassignments)} />
        <StatCard label="Gaps" value={fmtInt(gaps)} sub="unresolved on purpose" />
      </section>
      <div className="flex-1 min-h-0 grid grid-cols-2 gap-4">
        <Card className="min-h-0 overflow-y-auto space-y-4">
          {tl.isPending ? (
            <Empty title="Loading bindings…" />
          ) : bindings.length === 0 ? (
            <Empty title={`No bindings for ${ip}.`}>
              The resolver answers nothing for an address no DHCP, RADIUS or VPN record has bound. It never guesses.
            </Empty>
          ) : (
            <>
              <Lanes bindings={bindings} start={start} end={until} utc={utc} events={fw} />
              <p className="text-label text-text-muted">
                User lanes come from RADIUS/VPN, host lanes from DHCP. Ticks are firewall events on {ip}: white where a
                user was resolved, muted where none was.
              </p>
            </>
          )}
          <div>
            <Label className="block mb-2">Firewall events on {ip}</Label>
            <Table>
              <thead>
                <tr>
                  <Th dense>Time</Th>
                  <Th dense>Source</Th>
                  <Th dense>Resolved user</Th>
                </tr>
              </thead>
              <tbody>
                {fw
                  .slice(-40)
                  .reverse()
                  .map((e, i) => (
                    <tr key={e.event_id} className={rowClass(i)}>
                      <Td dense className="font-mono text-code text-text-muted">
                        {fmtClock(e.event_time ?? e.received_at, utc)}
                      </Td>
                      <Td dense>{productName(e.vendor, e.product)}</Td>
                      <Td dense className={cx(!user(e) && 'text-text-muted')}>
                        {user(e) ?? 'none (no claim covers this time)'}
                      </Td>
                    </tr>
                  ))}
              </tbody>
            </Table>
          </div>
        </Card>
        <Card pad={false} className="min-h-0 overflow-y-auto">
          <Table>
            <colgroup>
              <col className="w-20" />
              <col />
              <col />
              <col />
              <col className="hidden xl:table-column w-28" />
            </colgroup>
            <thead className="sticky top-0">
              <tr>
                <Th dense>Kind</Th>
                <Th dense>Holder</Th>
                <Th dense>From</Th>
                <Th dense>To</Th>
                <Th dense className="hidden xl:table-cell">
                  Evidence
                </Th>
              </tr>
            </thead>
            <tbody>
              {bindings.map((b, i) => (
                <tr key={i} className={rowClass(i)}>
                  <Td dense className="uppercase">
                    {b.kind}
                  </Td>
                  <Td dense title={`${b.mac} · evidence ${b.evidence.map((x) => '#' + x.record_id).join(', ')}`}>
                    {b.user || b.host}
                  </Td>
                  <Td dense className="font-mono text-code">
                    {fmtClock(b.valid_from, utc)}
                  </Td>
                  <Td dense className="font-mono text-code">
                    {b.valid_to ? fmtClock(b.valid_to, utc) : 'open'}
                  </Td>
                  <Td
                    dense
                    className="hidden xl:table-cell font-mono text-code text-text-muted"
                    title="Identity records in the vault that justify this binding"
                  >
                    {b.evidence.map((x) => `#${x.record_id}`).join(', ')}
                  </Td>
                </tr>
              ))}
            </tbody>
          </Table>
          {bindings.length > 0 && (
            <p className="px-card py-3 text-label text-text-muted">
              Times are {utc ? 'UTC' : 'in this browser’s zone'}; the window runs{' '}
              {fmtDateTime(new Date(start).toISOString(), utc)} to {fmtDateTime(new Date(until).toISOString(), utc)}.
            </p>
          )}
        </Card>
      </div>
    </div>
  );
}

function user(e: NormalizedEvent): string | undefined {
  return e.entities.find((x) => x.type === 'user')?.id;
}

function Lanes({
  bindings,
  start,
  end,
  utc,
  events,
}: {
  bindings: Binding[];
  start: number;
  end: number;
  utc: boolean;
  events: NormalizedEvent[];
}) {
  const span = end - start;
  const pos = (t: number) => `${((t - start) / span) * 100}%`;
  const lanes: { label: string; items: Binding[]; strength: string }[] = [
    { label: 'User', items: bindings.filter((b) => b.user), strength: 'opacity-70' },
    { label: 'Host', items: bindings.filter((b) => !b.user), strength: 'opacity-40' },
  ];
  return (
    <div className="space-y-2" role="img" aria-label="Binding timeline">
      {lanes.map((lane) => (
        <div key={lane.label} className="grid grid-cols-[48px_minmax(0,1fr)] items-center gap-3">
          <Label>{lane.label}</Label>
          <div className="relative h-8 bg-canvas border border-border rounded-button overflow-hidden">
            {lane.items.map((b, i) => {
              const from = Date.parse(b.valid_from);
              const to = b.valid_to ? Date.parse(b.valid_to) : end;
              return (
                <div
                  key={i}
                  className="absolute inset-y-1 rounded-bar overflow-hidden"
                  style={{ left: pos(from), width: `max(2px, ${((to - from) / span) * 100}%)` }}
                  title={`${b.user || b.host} · ${fmtClock(b.valid_from, utc)} → ${b.valid_to ? fmtClock(b.valid_to, utc) : 'open'} · evidence ${b.evidence.map((x) => '#' + x.record_id).join(', ')}`}
                >
                  <span className={cx('absolute inset-0 bg-lavender', lane.strength)} />
                  <span className="relative px-2 text-label font-semibold text-canvas whitespace-nowrap leading-6">
                    {b.user || b.host}
                  </span>
                </div>
              );
            })}
          </div>
        </div>
      ))}
      <div className="grid grid-cols-[48px_minmax(0,1fr)] items-center gap-3">
        <Label>Events</Label>
        <div className="relative h-6 border-b border-border">
          {events.map((e) => {
            const t = Date.parse(e.event_time ?? e.received_at);
            if (t < start || t > end) return null;
            return (
              <span
                key={e.event_id}
                className={cx('absolute top-1 bottom-0 w-px', user(e) ? 'bg-text-primary' : 'bg-text-muted opacity-50')}
                style={{ left: pos(t) }}
                title={`${fmtClock(e.event_time ?? e.received_at, utc)} · ${user(e) ?? 'no user'}`}
              />
            );
          })}
        </div>
      </div>
      <div className="grid grid-cols-[48px_minmax(0,1fr)] gap-3 text-label text-text-muted font-mono">
        <span />
        <div className="flex justify-between">
          <span>{fmtClock(new Date(start).toISOString(), utc).slice(0, 5)}</span>
          <span>{fmtClock(new Date(end).toISOString(), utc).slice(0, 5)}</span>
        </div>
      </div>
    </div>
  );
}
