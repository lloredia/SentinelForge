import { render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import SubmitForm from './SubmitForm';

it('submits a parsed indicator', async () => {
  const user = userEvent.setup();
  const onSubmit = vi.fn(async () => {});
  const onClose = vi.fn();
  render(<SubmitForm isOpen onClose={onClose} onSubmit={onSubmit} />);

  await user.type(screen.getByLabelText('IOC Value'), '8.8.8.8');
  await user.selectOptions(screen.getByLabelText('Severity'), 'high');
  await user.type(screen.getByLabelText('Tags'), 'dns, google');
  await user.click(screen.getByRole('button', { name: 'Add Indicator' }));

  expect(onSubmit).toHaveBeenCalledWith({
    value: '8.8.8.8',
    severity: 'high',
    tags: ['dns', 'google'],
  });
  expect(onClose).toHaveBeenCalled();
});

it('keeps the form open when submit fails', async () => {
  const user = userEvent.setup();
  const onSubmit = vi.fn(async () => {
    throw new Error('unauthorized');
  });
  render(<SubmitForm isOpen onClose={() => {}} onSubmit={onSubmit} />);

  await user.type(screen.getByLabelText('IOC Value'), 'evil.example');
  await user.click(screen.getByRole('button', { name: 'Add Indicator' }));
  expect(await screen.findByRole('alert')).toHaveTextContent('unauthorized');
});
