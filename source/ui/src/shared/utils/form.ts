/**
 * Extract the first error message from a TanStack Form field.
 * Standard Schema validators (e.g. Zod) return issue objects with a `.message`
 * property, while custom validators may return plain strings.
 */
export function fieldError(field: { state: { meta: { errors: unknown[]
  isTouched: boolean } } }): string | undefined {
  if (!field.state.meta.isTouched) {
    return undefined
  }

  const first = field.state.meta.errors[0]

  if (first == null) {
    return undefined
  }

  if (typeof first === 'string') {
    return first
  }

  if (typeof first === 'object' && 'message' in first) {
    return String((first as { message: unknown }).message)
  }

  return String(first)
}
