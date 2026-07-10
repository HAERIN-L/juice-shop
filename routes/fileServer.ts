/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import path from 'node:path'
import { type Request, type Response, type NextFunction } from 'express'

import * as utils from '../lib/utils'
import * as security from '../lib/insecurity'
import { challenges } from '../data/datacache'
import * as challengeUtils from '../lib/challengeUtils'

export function servePublicFiles () {
  return ({ params, query }: Request, res: Response, next: NextFunction) => {
    const file = params.file

    if (!file.includes('/')) {
      verify(file, res, next)
    } else {
      res.status(403)
      next(new Error('File names cannot contain forward slashes!'))
    }
  }

  function verify (file: string, res: Response, next: NextFunction) {
    // [취약] Null Byte 제거 후 재검증 없이 파일 전송 — 확장자 필터 우회 가능
    // if (file && (endsWithAllowlistedFileType(file) || (file === 'incident-support.kdbx'))) {
    //   file = security.cutOffPoisonNullByte(file)
    //   res.sendFile(path.resolve('ftp/', file))
    // }

    // [보안] Null Byte 포함 시 즉시 차단, cutOff 후 재검증
    if (file.includes('%00') || file.includes('\0')) {
      res.status(400)
      next(new Error('Invalid filename'))
      return
    }
    const cleanFile = security.cutOffPoisonNullByte(file)
    if (cleanFile && (endsWithAllowlistedFileType(cleanFile) || (cleanFile === 'incident-support.kdbx'))) {
      challengeUtils.solveIf(challenges.directoryListingChallenge, () => { return cleanFile.toLowerCase() === 'acquisitions.md' })
      verifySuccessfulPoisonNullByteExploit(cleanFile)
      res.sendFile(path.resolve('ftp/', cleanFile))
    } else {
      res.status(403)
      next(new Error('Only .md and .pdf files are allowed!'))
    }
  }

  function verifySuccessfulPoisonNullByteExploit (file: string) {
    challengeUtils.solveIf(challenges.easterEggLevelOneChallenge, () => { return file.toLowerCase() === 'eastere.gg' })
    challengeUtils.solveIf(challenges.forgottenDevBackupChallenge, () => { return file.toLowerCase() === 'package.json.bak' })
    challengeUtils.solveIf(challenges.forgottenBackupChallenge, () => { return file.toLowerCase() === 'coupons_2013.md.bak' })
    challengeUtils.solveIf(challenges.misplacedSignatureFileChallenge, () => { return file.toLowerCase() === 'suspicious_errors.yml' })

    challengeUtils.solveIf(challenges.nullByteChallenge, () => {
      return challenges.easterEggLevelOneChallenge.solved || challenges.forgottenDevBackupChallenge.solved || challenges.forgottenBackupChallenge.solved ||
        challenges.misplacedSignatureFileChallenge.solved || file.toLowerCase() === 'encrypt.pyc'
    })
  }

  function endsWithAllowlistedFileType (param: string) {
    return utils.endsWith(param, '.md') || utils.endsWith(param, '.pdf')
  }
}
