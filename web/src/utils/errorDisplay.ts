import {
  buildUiError,
  ERROR_CATALOG,
  ERROR_CODES,
  lookupErrorEntry,
  type ErrorCode,
  type UiError,
} from '../generated/errorCatalog';

export interface ApiErrorLike {
  readonly name?: string;
  readonly status: number;
  readonly code: string;
  readonly message: string;
}

export type ErrorDisplayContext = 'authenticated' | 'unauthenticated';

export interface ResolveUiErrorOptions {
  readonly context?: ErrorDisplayContext;
  readonly fallbackTitle?: string;
  readonly fallbackMessage?: string;
  readonly params?: Readonly<Record<string, string | number>>;
}

export interface FormattedToastError {
  readonly title: string;
  readonly detail: string;
  readonly uiError: UiError;
}

const CJK_RE = /[\u4e00-\u9fff]/;
const DEVICE_ID_RE = /\b(\d{9})\b/;
const PLACEHOLDER_RE = /\{([a-z][a-z0-9_]*)\}/g;
const TERMINAL_PUNCT_RE = /[。！？.!?；;：:]$/;

const DEFAULT_PARAM_VALUES: Readonly<Record<string, string>> = {
  device_id: '指定编号',
  host: '目标服务器',
  tool_name: '目标工具',
  max_count: '8',
  port: '指定端口',
  codec: '当前',
};

export function isApiErrorLike(err: unknown): err is ApiErrorLike {
  if (typeof err !== 'object' || err === null) {
    return false;
  }
  const candidate = err as Partial<ApiErrorLike>;
  return (
    typeof candidate.status === 'number' &&
    typeof candidate.code === 'string' &&
    typeof candidate.message === 'string'
  );
}

function fallbackCodeForHttpStatus(status: number): ErrorCode {
  if (status === 0) return ERROR_CODES.NETWORK_UNREACHABLE;
  if (status === 400) return ERROR_CODES.VALIDATION_INVALID_INPUT;
  if (status === 401) return ERROR_CODES.AUTH_UNAUTHORIZED;
  if (status === 403) return ERROR_CODES.AUTH_FORBIDDEN;
  if (status === 404) return ERROR_CODES.SERVER_NOT_FOUND;
  if (status === 409) return ERROR_CODES.SERVER_CONFLICT;
  if (status === 413) return ERROR_CODES.VALIDATION_PAYLOAD_TOO_LARGE;
  if (status === 429) return ERROR_CODES.NETWORK_RATE_LIMITED;
  if (status === 502 || status === 503 || status === 504) {
    return ERROR_CODES.SERVER_UNAVAILABLE;
  }
  if (status >= 500) return ERROR_CODES.SERVER_INTERNAL_ERROR;
  return ERROR_CODES.COMMON_UNKNOWN;
}

function normalizeExplicitParamValue(value: string | number | undefined): string | undefined {
  if (value === undefined) return undefined;
  const text = String(value).trim();
  return text.length > 0 ? text : undefined;
}

function buildSafeTemplateParams(
  canonicalCode: ErrorCode,
  rawDetail: string | undefined,
  explicitParams?: Readonly<Record<string, string | number>>,
): Record<string, string> | undefined {
  const entry = ERROR_CATALOG[canonicalCode];
  if (!entry || entry.params.length === 0) {
    return undefined;
  }

  const resolved: Record<string, string> = {};
  for (const paramName of entry.params) {
    const explicit =
      explicitParams && Object.prototype.hasOwnProperty.call(explicitParams, paramName)
        ? normalizeExplicitParamValue(explicitParams[paramName])
        : undefined;
    if (explicit !== undefined) {
      resolved[paramName] = explicit;
      continue;
    }

    if (paramName === 'device_id' && rawDetail) {
      const matched = DEVICE_ID_RE.exec(rawDetail);
      if (matched) {
        resolved[paramName] = matched[1];
        continue;
      }
    }

    resolved[paramName] = Object.prototype.hasOwnProperty.call(DEFAULT_PARAM_VALUES, paramName)
      ? DEFAULT_PARAM_VALUES[paramName]
      : '指定项';
  }

  return resolved;
}

function sanitizeRenderedCopy(text: string): string {
  return text
    .replace(PLACEHOLDER_RE, '指定项')
    .replace(/\s{2,}/g, ' ')
    .trim();
}

function hasLocalizedText(detail: string | undefined): detail is string {
  if (!detail) return false;
  const trimmed = detail.trim();
  return trimmed.length > 0 && CJK_RE.test(trimmed);
}

interface CopyOverride {
  readonly title?: string;
  readonly message: string;
  readonly suggestion: string;
}

/**
 * Maps well-known backend business/validation error messages into precise Chinese copy
 * for authenticated management/form workflows. Never invoked on unauthenticated auth pages.
 */
function resolveAuthenticatedBusinessOverride(
  canonicalCode: ErrorCode,
  rawWireCode: string,
  rawDetail: string | undefined,
): CopyOverride | undefined {
  const detail = (rawDetail ?? '').trim();
  const detailLower = detail.toLowerCase();
  const wireLower = rawWireCode.trim().toLowerCase();

  // Admin protection / business guards (real server returns 403 forbidden; mock returns 409)
  if (
    canonicalCode === ERROR_CODES.AUTH_FORBIDDEN ||
    canonicalCode === ERROR_CODES.SERVER_CONFLICT
  ) {
    if (
      detailLower.includes('cannot demote or disable the last active admin') ||
      (wireLower === 'last_admin_protected' && detail.includes('禁用'))
    ) {
      return {
        title: '禁止修改最后一个管理员',
        message: '系统至少需要保留一名启用状态的管理员，不能禁用或降权最后一个活跃管理员。',
        suggestion: '请先新增或启用其他管理员账号后再执行此操作。',
      };
    }
    if (
      detailLower.includes('cannot delete the last active admin') ||
      wireLower === 'last_admin_protected'
    ) {
      return {
        title: '禁止删除最后一个管理员',
        message: '系统至少需要保留一名启用状态的管理员，不能删除最后一个活跃管理员。',
        suggestion: '请先新增其他管理员账号后再执行删除操作。',
      };
    }
    if (
      wireLower === 'cannot_delete_self' ||
      detailLower.includes('cannot delete self') ||
      detailLower.includes('cannot delete current')
    ) {
      return {
        title: '无法删除当前登录账号',
        message: '不能删除当前正在登录的管理员账号。',
        suggestion: '请切换至其他管理员账号后再执行删除操作。',
      };
    }
    if (
      wireLower === 'email_conflict' ||
      detailLower.includes('email is already in use') ||
      (detailLower.includes('email') && detailLower.includes('already registered'))
    ) {
      return {
        title: '邮箱已被占用',
        message: hasLocalizedText(detail) ? detail : '该邮箱地址已被其他账号使用。',
        suggestion: '请更换其他未注册的邮箱地址后重试。',
      };
    }
  }

  // Field-level validation details on authenticated forms
  if (canonicalCode === ERROR_CODES.VALIDATION_INVALID_INPUT) {
    if (detailLower.includes('password length must be between 8 and 128 bytes')) {
      return {
        title: '密码长度不符合要求',
        message: '密码长度（按 UTF-8 字节计）必须在 8 到 128 字节之间。',
        suggestion: '请调整密码长度后重新提交（中文或特殊字符可能占用多个字节）。',
      };
    }
    if (detailLower.includes('password must not contain nul')) {
      return {
        title: '密码包含非法字符',
        message: '密码中不能包含空字符（NUL）。',
        suggestion: '请移除非法字符后重新输入。',
      };
    }
    if (detailLower.includes('new password must differ from current password')) {
      return {
        title: '新密码不能与原密码相同',
        message: '新密码与当前正在使用的密码一致。',
        suggestion: '请设置一个与当前密码不同的新密码。',
      };
    }
    if (
      detailLower.includes('invalid email format') ||
      detailLower.includes('email must contain') ||
      detailLower.includes('email must be') ||
      detailLower.includes('email must not contain') ||
      detailLower.includes('email is required')
    ) {
      return {
        title: '邮箱格式不正确',
        message: '输入的邮箱地址格式无效、超出长度限制或包含非法字符。',
        suggestion: '请输入规范的邮箱地址（例如 admin@example.com）后重试。',
      };
    }
    if (detailLower.includes('display_name')) {
      return {
        title: '显示名称不符合要求',
        message: '显示名称超出最大长度限制或包含非法控制字符。',
        suggestion: '请精简显示名称并移除控制字符后重新提交。',
      };
    }
    if (detailLower.includes('invalid role')) {
      return {
        title: '账号角色参数无效',
        message: '提交的账号角色不被服务器支持。',
        suggestion: '请选择有效角色（admin 或 user）后重试。',
      };
    }
    if (detailLower.includes('invalid status')) {
      return {
        title: '账号状态参数无效',
        message: '提交的账号状态不被服务器支持。',
        suggestion: '请选择有效状态（active 或 disabled）后重试。',
      };
    }
    if (detailLower.includes('device_id')) {
      return {
        title: '设备编号格式无效',
        message: '设备编号必须为有效的 9 位数字。',
        suggestion: '请核对 9 位设备编号后重试。',
      };
    }
  }

  // Preserve explicit localized Chinese detail for validation/conflict/unknown without appending conflicting suggestion
  if (
    hasLocalizedText(detail) &&
    (canonicalCode === ERROR_CODES.VALIDATION_INVALID_INPUT ||
      canonicalCode === ERROR_CODES.SERVER_CONFLICT ||
      canonicalCode === ERROR_CODES.COMMON_UNKNOWN)
  ) {
    return {
      message: detail,
      suggestion: '',
    };
  }

  return undefined;
}

/**
 * Resolves any thrown error (primarily `ApiError`, including `network_error` and `auth_superseded`)
 * into a structured Chinese `UiError` backed by `TokenBoom/rabbitcontrol-spec`.
 */
export function resolveUiError(
  err: unknown,
  options?: ResolveUiErrorOptions,
): UiError {
  const context: ErrorDisplayContext = options?.context ?? 'authenticated';

  if (isApiErrorLike(err)) {
    const rawCode = err.code.trim();
    const entry = lookupErrorEntry(rawCode);
    const resolvedCode: ErrorCode = entry
      ? entry.code
      : fallbackCodeForHttpStatus(err.status);
    const safeParams = buildSafeTemplateParams(
      resolvedCode,
      context === 'authenticated' ? err.message : undefined,
      options?.params,
    );
    const built = buildUiError(resolvedCode, {
      platform: 'web',
      params: safeParams,
      status: err.status,
      detail: context === 'authenticated' && err.message ? err.message : undefined,
    });

    const override =
      context === 'authenticated'
        ? resolveAuthenticatedBusinessOverride(resolvedCode, rawCode, err.message)
        : undefined;

    return {
      ...built,
      title: sanitizeRenderedCopy(override?.title ?? built.title),
      message: sanitizeRenderedCopy(override?.message ?? built.message),
      suggestion: sanitizeRenderedCopy(
        override !== undefined ? override.suggestion : built.suggestion,
      ),
    };
  }

  const rawMessage = err instanceof Error ? err.message.trim() : '';
  const built = buildUiError(ERROR_CODES.COMMON_UNKNOWN, {
    platform: 'web',
    params: options?.params,
    detail: context === 'authenticated' && rawMessage ? rawMessage : undefined,
  });

  if (options?.fallbackTitle || options?.fallbackMessage) {
    return {
      ...built,
      title: sanitizeRenderedCopy(options.fallbackTitle ?? built.title),
      message: sanitizeRenderedCopy(options.fallbackMessage ?? built.message),
      suggestion: sanitizeRenderedCopy(built.suggestion),
    };
  }
  return {
    ...built,
    title: sanitizeRenderedCopy(built.title),
    message: sanitizeRenderedCopy(built.message),
    suggestion: sanitizeRenderedCopy(built.suggestion),
  };
}

/**
 * Formats a `UiError` into concise Chinese prose with guaranteed sentence punctuation.
 */
export function formatUiErrorText(uiError: UiError): string {
  const message = uiError.message.trim();
  const suggestion = uiError.suggestion.trim();
  if (!suggestion) {
    return message;
  }
  if (!message) {
    return suggestion;
  }
  return TERMINAL_PUNCT_RE.test(message) ? `${message}${suggestion}` : `${message}。${suggestion}`;
}

/**
 * Resolves an error and formats it into a user-friendly Chinese message string.
 */
export function formatApiErrorMessage(
  err: unknown,
  options?: ResolveUiErrorOptions,
): string {
  const uiError = resolveUiError(err, options);
  return formatUiErrorText(uiError);
}

/**
 * Resolves an error into `{ title, detail, uiError }` for `useToast().pushToast('error', title, detail)`.
 */
export function formatApiErrorToast(
  err: unknown,
  options?: ResolveUiErrorOptions,
): FormattedToastError {
  const uiError = resolveUiError(err, options);
  return {
    title: uiError.title,
    detail: formatUiErrorText(uiError),
    uiError,
  };
}
