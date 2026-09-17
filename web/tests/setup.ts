import { enableAutoUnmount } from '@vue/test-utils'
import { afterEach, beforeEach, vi } from 'vitest'

import { installApiMock } from './support/api'

beforeEach(() => {
  // Tests must opt in to every API response. An undeclared request is rejected
  // locally so the suite can never fall through to a real backend.
  installApiMock({})
})

afterEach(() => {
  vi.restoreAllMocks()
  vi.unstubAllGlobals()
})

enableAutoUnmount(afterEach)
