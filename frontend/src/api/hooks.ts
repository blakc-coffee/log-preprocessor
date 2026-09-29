import { useInfiniteQuery, useMutation, useQuery, useQueryClient, type QueryKey } from '@tanstack/react-query';
import { api, ApiError } from './client';
import type {
  Activation,
  ChainReport,
  DriftAlert,
  DryRunResult,
  EventList,
  Health,
  Lineage,
  NormalizedEvent,
  ParserInfo,
  ParserVersions,
  Proposal,
  ProposalView,
  QuarantineList,
  RawResponse,
  RegistryRow,
  ReplayJob,
  Sample,
  Segments,
  Telemetry,
  Timeline,
} from './types';

// Retry transport failures a couple of times, never 4xx answers.
const retry = (n: number, e: unknown) => n < 2 && !(e instanceof ApiError && e.status >= 400 && e.status < 500);

export function useHealth() {
  return useQuery({
    queryKey: ['health'],
    queryFn: () => api.get<Health>('/healthz'),
    refetchInterval: 5000,
    retry: false,
  });
}

// EPS samples for the sparkline, appended as telemetry arrives (at most 64,
// one per 2 s poll: about two minutes). Kept beside the query rather than in
// component state so a remount keeps the history.
const epsRing: number[] = [];

export function epsHistory(): number[] {
  return epsRing.slice();
}

export function useTelemetry() {
  return useQuery({
    queryKey: ['telemetry'],
    queryFn: async ({ signal }) => {
      const t = await api.get<Telemetry>('/api/telemetry', undefined, signal);
      epsRing.push(t.eps_1m);
      if (epsRing.length > 64) epsRing.shift();
      return t;
    },
    refetchInterval: 2000,
    retry,
  });
}

export const EVENT_PAGE = 200;

export function useEventPages(filters: Record<string, string>) {
  return useInfiniteQuery({
    queryKey: ['events', filters],
    queryFn: ({ pageParam, signal }) =>
      api.get<EventList>('/api/events', { ...filters, limit: EVENT_PAGE, cursor: pageParam }, signal),
    initialPageParam: undefined as string | undefined,
    getNextPageParam: (last) => last.next_cursor ?? undefined,
    retry,
  });
}

export function fetchTail(filters: Record<string, string>, sinceSeq: number, signal?: AbortSignal) {
  return api.get<EventList>('/api/events', { ...filters, since_seq: sinceSeq, limit: 500 }, signal);
}

export function useEvent(id: string | undefined) {
  return useQuery({
    queryKey: ['event', id],
    queryFn: () => api.get<NormalizedEvent>(`/api/events/${encodeURIComponent(id!)}`),
    enabled: !!id,
    retry,
  });
}

export function useRaw(id: string | undefined) {
  return useQuery({
    queryKey: ['raw', id],
    queryFn: () => api.get<RawResponse>(`/api/events/${encodeURIComponent(id!)}/raw`),
    enabled: !!id,
    retry,
  });
}

export function useLineage(id: string | undefined) {
  return useQuery({
    queryKey: ['lineage', id],
    queryFn: () => api.get<Lineage>(`/api/lineage/${encodeURIComponent(id!)}`),
    enabled: !!id,
    retry,
    // An unsealed segment seals within seconds: keep asking until it does.
    refetchInterval: (q) => (q.state.data && !q.state.data.sealed ? 3000 : false),
  });
}

export function useQuarantine(params: Record<string, string> = {}) {
  return useQuery({
    queryKey: ['quarantine', params],
    queryFn: () => api.get<QuarantineList>('/api/quarantine', { limit: 200, ...params }),
    refetchInterval: 3000,
    retry,
  });
}

export function useSamples(source: string | undefined, status: 'quarantined' | 'parsed' | 'any', limit = 5) {
  return useQuery({
    queryKey: ['samples', source, status, limit],
    queryFn: () => api.get<{ samples: Sample[] }>('/api/samples', { source_id: source, status, limit }),
    enabled: !!source,
    retry,
  });
}

export function useDrift() {
  return useQuery({
    queryKey: ['drift'],
    queryFn: () => api.get<{ alerts: DriftAlert[] }>('/api/drift'),
    refetchInterval: 3000,
    retry,
  });
}

export function useProposals() {
  return useQuery({
    queryKey: ['proposals'],
    queryFn: () => api.get<{ proposals: Proposal[] }>('/api/proposals'),
    refetchInterval: 3000,
    retry,
  });
}

export function useProposal(id: string | undefined) {
  return useQuery({
    queryKey: ['proposal', id],
    queryFn: () => api.get<ProposalView>(`/api/proposals/${encodeURIComponent(id!)}`),
    enabled: !!id,
    retry,
  });
}

export function useReplay(jobId: string | undefined) {
  return useQuery({
    queryKey: ['replay', jobId],
    queryFn: () => api.get<ReplayJob>(`/api/replay/${encodeURIComponent(jobId!)}`),
    enabled: !!jobId,
    refetchInterval: (q) =>
      q.state.data && (q.state.data.state === 'done' || q.state.data.state === 'failed') ? false : 1000,
    retry,
  });
}

export function useParsers() {
  return useQuery({
    queryKey: ['parsers'],
    queryFn: () => api.get<{ parsers: ParserInfo[] }>('/api/parsers'),
    refetchInterval: 10000,
    retry,
  });
}

export function useParserVersions(id: string | undefined) {
  return useQuery({
    queryKey: ['parserVersions', id],
    queryFn: () => api.get<ParserVersions>(`/api/parsers/${encodeURIComponent(id!)}/versions`),
    enabled: !!id,
    retry,
  });
}

export function useParserYAML(id: string | undefined, version: string | undefined) {
  return useQuery({
    queryKey: ['parserYAML', id, version],
    queryFn: () => api.get<string>(`/api/parsers/${encodeURIComponent(id!)}/versions/${encodeURIComponent(version!)}`),
    enabled: !!id && !!version,
    staleTime: Infinity, // a version file is immutable once written
    retry,
  });
}

export function useHistory() {
  return useQuery({
    queryKey: ['history'],
    queryFn: () => api.get<{ history: RegistryRow[] }>('/api/history'),
    refetchInterval: 10000,
    retry,
  });
}

export function useTimeline(ip: string | undefined, from?: string, to?: string) {
  return useQuery({
    queryKey: ['timeline', ip, from, to],
    queryFn: () => api.get<Timeline>('/api/identity/timeline', { ip, from, to }),
    enabled: !!ip,
    retry,
  });
}

export function useSegments() {
  return useQuery({
    queryKey: ['segments'],
    queryFn: () => api.get<Segments>('/api/vault/segments'),
    refetchInterval: 5000,
    retry,
  });
}

function useInvalidate() {
  const qc = useQueryClient();
  return (...keys: QueryKey[]) => keys.forEach((k) => qc.invalidateQueries({ queryKey: k }));
}

export function useDryRun(proposalId: string) {
  return useMutation({
    mutationFn: (yaml: string) =>
      api.post<DryRunResult>(`/api/proposals/${encodeURIComponent(proposalId)}/dryrun`, { yaml }),
  });
}

export function useApprove(proposalId: string) {
  const invalidate = useInvalidate();
  return useMutation({
    mutationFn: (b: { approved_by: string; comment: string; yaml?: string }) =>
      api.post<Activation>(`/api/proposals/${encodeURIComponent(proposalId)}/approve`, b),
    onSettled: () =>
      invalidate(['proposals'], ['proposal', proposalId], ['drift'], ['parsers'], ['history'], ['telemetry']),
  });
}

export function useReject(proposalId: string) {
  const invalidate = useInvalidate();
  return useMutation({
    mutationFn: (b: { by: string; comment: string }) =>
      api.post<Proposal>(`/api/proposals/${encodeURIComponent(proposalId)}/reject`, b),
    onSettled: () => invalidate(['proposals'], ['proposal', proposalId], ['history']),
  });
}

export function useRollback(parserId: string) {
  const invalidate = useInvalidate();
  return useMutation({
    mutationFn: (b: { to_version: string; by: string; comment: string; replay: boolean }) =>
      api.post<Activation>(`/api/parsers/${encodeURIComponent(parserId)}/rollback`, b),
    onSettled: () => invalidate(['parsers'], ['parserVersions', parserId], ['history']),
  });
}

export function useVerifyParser(parserId: string) {
  return useMutation({
    mutationFn: () => api.post<DryRunResult>(`/api/parsers/${encodeURIComponent(parserId)}/verify`, {}),
  });
}

export function useVerifyChain() {
  const invalidate = useInvalidate();
  return useMutation({
    mutationFn: (deep: boolean) => api.get<ChainReport>('/api/vault/verify', { deep }),
    onSettled: () => invalidate(['telemetry']),
  });
}
