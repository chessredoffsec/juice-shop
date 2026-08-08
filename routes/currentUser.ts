/*

* Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
* SPDX-License-Identifier: MIT
  */

import * as challengeUtils from '../lib/challengeUtils'
import { type Request, type Response } from 'express'
import { challenges } from '../data/datacache'
import * as security from '../lib/insecurity'

export function retrieveLoggedInUser () {
return (req: Request, res: Response) => {
let user
let response: any

const emptyUser = {
  id: undefined,
  email: undefined,
  lastLoginIp: undefined,
  profileImage: undefined
}

try {
  if (security.verify(req.cookies.token)) {
    user = security.authenticatedUsers.get(req.cookies.token)

    const fieldsParam = req.query?.fields as string | undefined
    const requestedFields = fieldsParam
      ? fieldsParam.split(',').map(field => field.trim())
      : []

    const allowedFields = new Set([
      'id',
      'email',
      'lastLoginIp',
      'profileImage'
    ])

    let baseUser: Record<string, unknown> = {}

    if (requestedFields.length > 0) {
      for (const field of requestedFields) {
        if (
          allowedFields.has(field) &&
          user?.data?.[field as keyof typeof user.data] !== undefined
        ) {
          baseUser[field] =
            user.data[field as keyof typeof user.data]
        }
      }
    } else {
      baseUser = {
        id: user?.data?.id,
        email: user?.data?.email,
        lastLoginIp: user?.data?.lastLoginIp,
        profileImage: user?.data?.profileImage
      }
    }

    response = { user: baseUser }
  } else {
    response = { user: emptyUser }
  }
} catch (err) {
  response = { user: emptyUser }
}

if (req.query.callback === undefined) {
  res.json(response)
} else {
  challengeUtils.solveIf(challenges.emailLeakChallenge, () => {
    return true
  })

  res.jsonp(response)
}

}
}
