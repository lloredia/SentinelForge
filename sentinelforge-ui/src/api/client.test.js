import { apiRequest } from './client';

describe('api client', () => {
  afterEach(() => {
    vi.unstubAllEnvs();
    vi.unstubAllGlobals();
  });

  it('sends the API key and parses a text body', async () => {
    vi.stubEnv('VITE_API_BASE', 'http://127.0.0.1:8080');
    vi.stubEnv('VITE_API_KEY', 'test-suite-api-key');
    const fetchMock = vi.fn(async () => ({
      ok: true,
      status: 201,
      text: async () => JSON.stringify({ id: 'abc' }),
    }));
    vi.stubGlobal('fetch', fetchMock);

    await expect(apiRequest('/api/v1/indicators', { method: 'POST' })).resolves.toEqual({
      id: 'abc',
    });
    expect(fetchMock).toHaveBeenCalledWith(
      'http://127.0.0.1:8080/api/v1/indicators',
      expect.objectContaining({
        method: 'POST',
        headers: expect.objectContaining({ 'X-API-Key': 'test-suite-api-key' }),
      }),
    );
  });

  it('surfaces the server error without throwing the raw body', async () => {
    vi.stubEnv('VITE_API_KEY', '');
    const fetchMock = vi.fn(async () => ({
      ok: false,
      status: 401,
      text: async () => JSON.stringify({ error: 'unauthorized' }),
    }));
    vi.stubGlobal('fetch', fetchMock);

    await expect(apiRequest('/api/v1/indicators')).rejects.toThrow('unauthorized');
    const headers = fetchMock.mock.calls[0][1].headers;
    expect(headers['X-API-Key']).toBeUndefined();
  });
});
