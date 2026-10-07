import { render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import SearchFilters from './SearchFilters';

it('reports search text and type filter changes', async () => {
  const user = userEvent.setup();
  const onSearch = vi.fn();
  const onFilter = vi.fn();
  render(
    <SearchFilters searchQuery="" filterType="all" onSearch={onSearch} onFilter={onFilter} />,
  );

  await user.type(screen.getByLabelText('Search indicators'), 'evil');
  expect(onSearch).toHaveBeenCalled();
  await user.selectOptions(screen.getByLabelText('Filter by IOC type'), 'domain');
  expect(onFilter).toHaveBeenCalledWith('domain');
});
