export const BUSINESS_ERROR_CODES = {
  PDF_TOO_LARGE: 'pdf_too_large',
  PDF_PASSWORD_PROTECTED: 'pdf_password_protected',
  PDF_INVALID: 'pdf_invalid',
  IMAGE_TOO_LARGE: 'image_too_large',
  IMAGE_UNSUPPORTED: 'image_unsupported',
  REQUEST_TOO_LARGE: 'request_too_large',
  PROMPT_TOO_LONG: 'prompt_too_long',
  AUTO_MODE_UNAVAILABLE: 'auto_mode_unavailable',
} as const

export type BusinessErrorCode =
  (typeof BUSINESS_ERROR_CODES)[keyof typeof BUSINESS_ERROR_CODES]

export const BUSINESS_ERROR_MEDIA_BLOCK_TYPES: Partial<
  Record<BusinessErrorCode, readonly ('document' | 'image')[]>
> = {
  [BUSINESS_ERROR_CODES.PDF_TOO_LARGE]: ['document'],
  [BUSINESS_ERROR_CODES.PDF_PASSWORD_PROTECTED]: ['document'],
  [BUSINESS_ERROR_CODES.PDF_INVALID]: ['document'],
  [BUSINESS_ERROR_CODES.IMAGE_TOO_LARGE]: ['image'],
  [BUSINESS_ERROR_CODES.IMAGE_UNSUPPORTED]: ['image'],
  [BUSINESS_ERROR_CODES.REQUEST_TOO_LARGE]: ['document', 'image'],
}
