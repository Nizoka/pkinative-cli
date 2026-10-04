// pkinative error → CLI error mapping: the ONLY place that reads `err.code`.
//
// Every engine call in a command runs through `guard()` / `guardAsync()`, so
// an autonomous caller always gets a stable CLASS (`error.code`, E_*), the
// exact CAUSE (`error.pkiCode`, pkinative's frozen code verbatim), the
// structured detail the engine knows, and a remedy phrased as CLI flags.
//
// The table is typed `satisfies Record<PkiErrorCode, …>`: an engine minor that
// adds a code fails `tsc` here instead of leaking as E_RUNTIME.

import {
    PkiCertificateError,
    PkiCmsError,
    PkiCryptoError,
    PkiEncodingError,
    PkiError,
    PkiKeyError,
    PkiLimitError,
    type PkiErrorCode,
} from '../core-bridge/index.js';
import { CliError, ErrorCode, type ErrorCodeValue, type ErrorDetail } from './error.js';
import { flagForLimit } from './limits.js';

type Mapping = readonly [code: ErrorCodeValue, exitCode: 1 | 2];

const USAGE: Mapping = [ErrorCode.USAGE, 2];
const INPUT: Mapping = [ErrorCode.INPUT, 1];
const PARSE: Mapping = [ErrorCode.PARSE, 1];
const SECURITY: Mapping = [ErrorCode.SECURITY, 1];
const LIMIT: Mapping = [ErrorCode.LIMIT, 1];
const UNSUPPORTED: Mapping = [ErrorCode.UNSUPPORTED, 1];
const CRYPTO: Mapping = [ErrorCode.CRYPTO, 1];
const PASSWORD: Mapping = [ErrorCode.PASSWORD, 1];
const CHECK: Mapping = [ErrorCode.CHECK_FAILED, 1];
const RUNTIME: Mapping = [ErrorCode.RUNTIME, 1];

/** The 57 frozen pkinative codes → CLI class + exit code. */
export const PKI_TO_CLI = {
    // base (5)
    PKI_INVALID_INPUT: INPUT,
    PKI_INVALID_OPTION: USAGE,
    PKI_API_MISUSE: USAGE,
    PKI_STRICT_DIAGNOSTIC: CHECK,
    PKI_INTERNAL: RUNTIME,
    // asn1 + oid (19)
    PKI_ASN1_TRUNCATED: PARSE,
    PKI_ASN1_TAG_INVALID: PARSE,
    PKI_ASN1_LENGTH_INVALID: PARSE,
    PKI_ASN1_LENGTH_NON_MINIMAL: PARSE,
    PKI_ASN1_LENGTH_OVERFLOW: PARSE,
    PKI_ASN1_INDEFINITE_LENGTH_FORBIDDEN: PARSE,
    PKI_ASN1_CONSTRUCTED_STRING_FORBIDDEN: PARSE,
    PKI_ASN1_CONSTRUCTED_FORM_INVALID: PARSE,
    PKI_ASN1_EOC_UNEXPECTED: PARSE,
    PKI_ASN1_TRAILING_DATA: PARSE,
    PKI_ASN1_UNEXPECTED_TAG: PARSE,
    PKI_ASN1_BOOLEAN_INVALID: PARSE,
    PKI_ASN1_INTEGER_INVALID: PARSE,
    PKI_ASN1_INTEGER_UNREPRESENTABLE: PARSE,
    PKI_ASN1_BIT_STRING_INVALID: PARSE,
    PKI_ASN1_NULL_INVALID: PARSE,
    PKI_ASN1_STRING_INVALID: PARSE,
    PKI_ASN1_TIME_INVALID: PARSE,
    PKI_ASN1_VALUE_OUT_OF_RANGE: INPUT,
    PKI_OID_INVALID: PARSE,
    // pem (7)
    PKI_PEM_NO_BLOCK: PARSE,
    PKI_PEM_LABEL_INVALID: INPUT,
    PKI_PEM_LABEL_MISMATCH: PARSE,
    PKI_PEM_UNEXPECTED_LABEL: INPUT,
    PKI_PEM_UNTERMINATED: PARSE,
    PKI_PEM_BASE64_INVALID: PARSE,
    PKI_PEM_HEADERS_FORBIDDEN: UNSUPPORTED,
    // x509 (10)
    PKI_X509_STRUCTURE_INVALID: PARSE,
    PKI_X509_VERSION_INVALID: PARSE,
    PKI_X509_NAME_INVALID: PARSE,
    PKI_X509_VALIDITY_INVALID: PARSE,
    PKI_X509_SPKI_INVALID: PARSE,
    PKI_X509_UNIQUE_ID_INVALID: PARSE,
    PKI_X509_EXTENSIONS_EMPTY: PARSE,
    PKI_X509_EXTENSION_DUPLICATE: PARSE,
    PKI_X509_EXTENSION_MALFORMED: PARSE,
    PKI_X509_GENERAL_NAME_INVALID: PARSE,
    // limits (2)
    PKI_LIMIT_EXCEEDED: LIMIT,
    PKI_LIMIT_INVALID: USAGE,
    // crypto (5)
    PKI_CRYPTO_UNAVAILABLE: CRYPTO,
    PKI_CRYPTO_ALGORITHM_UNSUPPORTED: UNSUPPORTED,
    PKI_CRYPTO_KEY_UNSUPPORTED: UNSUPPORTED,
    PKI_CRYPTO_ALGORITHM_REFUSED: SECURITY,
    PKI_CRYPTO_DECRYPTION_FAILED: PASSWORD,
    // cms (4)
    PKI_CMS_STRUCTURE_INVALID: PARSE,
    PKI_CMS_CONTENT_TYPE_UNEXPECTED: INPUT,
    PKI_CMS_VERSION_UNSUPPORTED: UNSUPPORTED,
    PKI_CMS_CONTENT_NOT_OCTET_STRING: UNSUPPORTED,
    // keys (4)
    PKI_KEY_STRUCTURE_INVALID: PARSE,
    PKI_KEY_VERSION_UNSUPPORTED: UNSUPPORTED,
    PKI_KEY_ENCRYPTION_UNSUPPORTED: SECURITY,
    PKI_KEY_MAC_UNSUPPORTED: SECURITY,
} as const satisfies Record<PkiErrorCode, Mapping>;

/** Every frozen PKI_* error code (57), in table order. */
export const PKI_ERROR_CODES: readonly PkiErrorCode[] = Object.keys(PKI_TO_CLI) as PkiErrorCode[];

/**
 * The CLI flag(s) that lift an engine refusal: the command-line counterpart of
 * pkinative's own remedy, which names library options. Absent = no flag lifts
 * it (the input itself must change); `pkinative explain <code>` prints the
 * engine's full remedy.
 */
export const PKI_REMEDY = {
    PKI_ASN1_LENGTH_NON_MINIMAL: '--ber (the producer wrote BER, not DER)',
    PKI_ASN1_INDEFINITE_LENGTH_FORBIDDEN: '--ber (indefinite lengths are BER; common in CMS)',
    PKI_ASN1_CONSTRUCTED_STRING_FORBIDDEN: '--ber (constructed strings are BER)',
    PKI_ASN1_BOOLEAN_INVALID: '--ber (a non-0xFF TRUE is BER)',
    PKI_ASN1_TRAILING_DATA: 'pass exactly one object, or asn1 decode --sequence for concatenated objects',
    PKI_PEM_BASE64_INVALID: '--pem-mode lax (tolerates whitespace and missing padding)',
    PKI_PEM_UNEXPECTED_LABEL: 'pkinative pem decode <file> (lists the labels present)',
    PKI_STRICT_DIAGNOSTIC: 'drop --strict, or fix the producer the diagnostic names',
    PKI_CRYPTO_ALGORITHM_REFUSED: '--allow-sha1 (only for legacy material you already trust)',
    PKI_CRYPTO_DECRYPTION_FAILED: '--password-file <file> | --password-stdin | PKINATIVE_PASSWORD (check the password)',
    PKI_X509_EXTENSION_MALFORMED: 'cert inspect --raw-extensions (keeps every extension undecoded)',
    PKI_API_MISUSE: 'pkinative <command> --help (a required option is missing, e.g. --rsa-scheme)',
} as const satisfies Partial<Record<PkiErrorCode, string>>;

/** The remedy for a CliError: an explicit one wins, else the PKI_* table. */
export function remedyFor(err: CliError): string | undefined {
    if (err.remedy !== undefined) return err.remedy;
    if (err.pkiCode !== undefined && Object.hasOwn(PKI_REMEDY, err.pkiCode)) {
        return PKI_REMEDY[err.pkiCode as keyof typeof PKI_REMEDY];
    }
    return undefined;
}

function detailOf(err: PkiError): ErrorDetail | undefined {
    if (err instanceof PkiLimitError) {
        return { limit: err.limit, configured: err.configured, observed: err.observed };
    }
    const detail: Record<string, string | number> = {};
    if (err instanceof PkiCryptoError && err.algorithm !== undefined) detail['algorithm'] = err.algorithm;
    if (err instanceof PkiCertificateError || err instanceof PkiCmsError || err instanceof PkiKeyError) {
        if (err.path !== undefined) detail['path'] = err.path;
    }
    if (err instanceof PkiEncodingError || err instanceof PkiCertificateError || err instanceof PkiCmsError || err instanceof PkiKeyError) {
        if (err.offset !== undefined) detail['offset'] = err.offset;
    }
    return Object.keys(detail).length > 0 ? detail : undefined;
}

const FS_ERROR_CODES: ReadonlySet<string> = new Set([
    'ENOENT', 'EACCES', 'EPERM', 'EISDIR', 'ENOTDIR', 'ENOSPC', 'EEXIST',
    'EMFILE', 'ENFILE', 'EBUSY', 'EROFS', 'ELOOP', 'ENAMETOOLONG', 'EIO',
]);

/** True for a Node filesystem error with a known errno code. */
export function isFsError(err: unknown): err is NodeJS.ErrnoException {
    return err instanceof Error && typeof (err as NodeJS.ErrnoException).code === 'string'
        && FS_ERROR_CODES.has((err as NodeJS.ErrnoException).code as string);
}

/**
 * Convert any thrown value into a CliError carrying the right class, exit code
 * and pass-through cause. CliErrors are returned unchanged.
 */
export function mapPkiError(err: unknown, context: string): CliError {
    if (err instanceof CliError) return err;
    if (err instanceof PkiError) {
        const code = err.code as string;
        const [cliCode, exitCode] = Object.hasOwn(PKI_TO_CLI, code) ? PKI_TO_CLI[code as PkiErrorCode] : RUNTIME;
        const detail = detailOf(err as PkiError);
        const limitFlag = err instanceof PkiLimitError ? flagForLimit(err.limit) : undefined;
        return new CliError(`${context}: ${err.message}`, exitCode, cliCode, {
            pkiCode: code,
            ...(detail !== undefined ? { detail } : {}),
            ...(limitFlag !== undefined ? { remedy: `--${limitFlag} <value> (raise the bound for trusted input only)` } : {}),
        });
    }
    if (isFsError(err)) {
        const where = err.path !== undefined ? ` (${err.path})` : '';
        return new CliError(`${context}: ${String(err.code)}${where}`, 1, ErrorCode.IO);
    }
    const message = err instanceof Error ? err.message : String(err);
    return new CliError(`${context}: ${message}`, 1, ErrorCode.RUNTIME);
}

/** Run a synchronous engine call, translating any failure. */
export function guard<T>(context: string, fn: () => T): T {
    try {
        return fn();
    } catch (e) {
        throw mapPkiError(e, context);
    }
}

/** Run an asynchronous engine call, translating any failure. */
export async function guardAsync<T>(context: string, fn: () => Promise<T>): Promise<T> {
    try {
        return await fn();
    } catch (e) {
        throw mapPkiError(e, context);
    }
}
