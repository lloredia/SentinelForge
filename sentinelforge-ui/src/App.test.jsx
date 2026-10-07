import { render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import App from './App';

const indicator = {
  id: '22222222-2222-2222-2222-222222222222',
  value: 'evil.example',
  ioc_type: 'domain',
  severity: 'high',
  confidence: 80,
  threat_score: 70,
  tlp: 'amber',
  tags: ['c2'],
  first_seen: '2026-02-01T00:00:00Z',
  last_seen: '2026-02-02T00:00:00Z',
};

function jsonResponse(body, ok = true, status = 200) {
  return {
    ok,
    status,
    text: async () => JSON.stringify(body),
  };
}

beforeEach(() => {
  vi.stubGlobal(
    'fetch',
    vi.fn(async (url) => {
      const path = String(url);
      if (path.endsWith('/api/v1/stats')) {
        return jsonResponse({
          total_indicators: 1,
          new_today: 1,
          new_this_week: 1,
          active_sources: 0,
          recent_sightings: 3,
        });
      }
      if (path.includes('/api/v1/indicators/')) {
        return jsonResponse({
          indicator,
          enrichments: [
            {
              enrichment_type: 'dns',
              provider: 'dns',
              data: { a_records: ['1.2.3.4'] },
            },
          ],
        });
      }
      return jsonResponse({ data: [indicator], total: 1, page: 1, per_page: 50, total_pages: 1 });
    }),
  );
});

afterEach(() => {
  vi.unstubAllGlobals();
});

it('loads stats and opens enrichment for a selected indicator', async () => {
  const user = userEvent.setup();
  render(<App />);

  expect(await screen.findByText('evil.example')).toBeInTheDocument();
  expect(screen.getByText('Total IOCs')).toBeInTheDocument();
  expect(screen.getByText('Sightings (24h)')).toBeInTheDocument();
  expect(screen.getByText('3')).toBeInTheDocument();

  await user.click(screen.getByText('evil.example'));
  expect(await screen.findByText('Enrichment Data')).toBeInTheDocument();
  expect(screen.getByText(/1\.2\.3\.4/)).toBeInTheDocument();
});

it('shows a retry state when the API is unreachable', async () => {
  vi.stubGlobal(
    'fetch',
    vi.fn(async () => {
      throw new Error('network down');
    }),
  );
  render(<App />);
  expect(await screen.findByText('network down')).toBeInTheDocument();
  expect(screen.getByRole('button', { name: 'Retry Connection' })).toBeInTheDocument();
});
