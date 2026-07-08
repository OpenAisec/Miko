// desktop/src/api/kimoOAuth.ts

import { api, getBaseUrl } from './client'

export type KimoOAuthStatus =
  | { loggedIn: false }
  | {
      loggedIn: true
      expiresAt: number | null
      scopes: string[]
      subscriptionType: 'pro' | 'max' | 'team' | 'enterprise' | null
    }

function currentServerPort(): number {
  const port = new URL(getBaseUrl()).port
  const parsed = Number.parseInt(port, 10)
  if (!Number.isFinite(parsed) || parsed <= 0) {
    throw new Error(`Cannot determine server port from baseUrl: ${getBaseUrl()}`)
  }
  return parsed
}

export const kimoOAuthApi = {
  start() {
    return api.post<{ authorizeUrl: string; state: string }>(
      '/api/kimo-oauth/start',
      { serverPort: currentServerPort() },
    )
  },

  status() {
    return api.get<KimoOAuthStatus>('/api/kimo-oauth')
  },

  logout() {
    return api.delete<{ ok: true }>('/api/kimo-oauth')
  },
}
