import { CUSTOM_HEADER_SITE_ID_KEY, DEFAULT_ERROR_MESSAGE } from '@constants'
import {
  ACCESS_TOKEN,
  AUTH_USER_ID,
  CLAIM_NAME,
  REFRESH_TOKEN,
  SERVER_API_URL,
  SITE_ID,
} from '@constants/env'
import axios from 'axios'
import Cookies from 'cookies'
import { NextApiRequest, NextApiResponse } from 'next'

export default async (req: NextApiRequest, res: NextApiResponse) => {
  const rawUrl = req.url || ''
  const targetUrl = rawUrl.replace(/^\/api\/login/, '')

  if (!targetUrl || targetUrl.indexOf('undefined') > -1) {
    res.status(500).json({ message: DEFAULT_ERROR_MESSAGE })
    res.end()
    return
  }

  const headers: Record<string, string> = {
    'Content-Type': 'application/json',
  }
  headers[CUSTOM_HEADER_SITE_ID_KEY] = SITE_ID || '1'

  // silent refresh
  if (targetUrl.indexOf('/refresh') > -1) {
    const cookies = new Cookies(req, res)
    headers[CLAIM_NAME] = cookies.get(REFRESH_TOKEN) || ''

    if (!headers[CLAIM_NAME]) {
      console.warn(`can't refresh`)
      res.status(401).json({ message: 'Invalid Credentials 🥺' })
      return
    }
  }

  // GET/HEAD 이외의 요청만 body를 JSON 문자열로 직렬화하여 전달
  const hasBody = req.method !== 'GET' && req.method !== 'HEAD' && req.body !== undefined && req.body !== ''
  const requestBody = hasBody
    ? typeof req.body === 'string'
      ? req.body
      : JSON.stringify(req.body)
    : undefined

  try {
    const result = await fetch(`${SERVER_API_URL}${targetUrl}`, {
      method: req.method,
      headers,
      ...(requestBody ? { body: requestBody } : {}),
    })

    if (result) {
      const refreshToken = result.headers.get(REFRESH_TOKEN)
      const accessToken = result.headers.get(ACCESS_TOKEN)
      const userId = result.headers.get(AUTH_USER_ID)
      const cookies = new Cookies(req, res)

      if (refreshToken) {
        cookies.set(REFRESH_TOKEN, refreshToken, {
          httpOnly: true,
          sameSite: 'lax', // CSRF protection
        })
      }

      if (accessToken) {
        const payload: Record<string, string | null> = {}
        payload[ACCESS_TOKEN] = accessToken
        payload[AUTH_USER_ID] = userId
        axios.defaults.headers.common[CLAIM_NAME] = accessToken
        axios.defaults.headers.common[AUTH_USER_ID] = userId || ''

        res.status(200).json(payload)
      } else {
        res.status(result.status).json({ message: 'Invalid Credentials 🥺' })
      }
    } else {
      res.status(401).json({ message: 'Invalid Credentials 🥺' })
    }
  } catch (error: any) {
    console.error(error)
    res.status(500).json({ message: error?.message || DEFAULT_ERROR_MESSAGE })
  }
}
