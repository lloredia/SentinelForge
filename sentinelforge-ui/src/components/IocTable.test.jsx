import { render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import IocTable from './IocTable';

const indicator = {
  id: '11111111-1111-1111-1111-111111111111',
  value: '8.8.8.8',
  ioc_type: 'ip',
  severity: 'low',
  threat_score: 12,
  tags: ['dns'],
  last_seen: '2026-01-02T03:04:00Z',
};

it('renders an empty state', () => {
  render(<IocTable indicators={[]} onSelect={() => {}} />);
  expect(screen.getByText('No indicators found')).toBeInTheDocument();
});

it('selects a row', async () => {
  const user = userEvent.setup();
  const onSelect = vi.fn();
  render(<IocTable indicators={[indicator]} onSelect={onSelect} />);
  await user.click(screen.getByText('8.8.8.8'));
  expect(onSelect).toHaveBeenCalledWith(indicator);
  expect(screen.getByText('LOW')).toBeInTheDocument();
});
