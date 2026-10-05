/**
 * Stable, machine-readable failure classes of the `--json` error envelope.
 * Part of the CLI's public contract: an agent branches on the CLASS here and
 * reads the exact CAUSE in `pkiCode` (pkinative's frozen code, verbatim).
 */
export const ErrorCode = {
    /** Missing or invalid flag, argument or option value (exit 2). */
    USAGE: 'E_USAGE',
    /** A value the user supplied is not acceptable: a spec document, a label, a range. */
    INPUT: 'E_INPUT',
    /** The bytes are not the DER, PEM or JSON structure they claim to be. */
    PARSE: 'E_PARSE',
    /** Filesystem or stream failure, including a refused overwrite. */
    IO: 'E_IO',
    /** A security policy refused the input: SHA-1 without --allow-sha1, PBES1, a legacy MAC. */
    SECURITY: 'E_SECURITY',
    /** A named bound (a pkinative limit or a CLI read cap) was exceeded. */
    LIMIT: 'E_LIMIT',
    /** The runtime or the engine does not support the algorithm, key or structure. */
    UNSUPPORTED: 'E_UNSUPPORTED',
    /** Web Crypto could not run the operation the input requires. */
    CRYPTO: 'E_CRYPTO',
    /** A password is wrong: a decryption or a PKCS#12 MAC fails under it. A missing password is E_USAGE. */
    PASSWORD: 'E_PASSWORD',
    /** A named item (an error code, an extension, a block) does not exist. */
    NOT_FOUND: 'E_NOT_FOUND',
    /** A signature, chain, request, timestamp or MAC verdict is negative. */
    VERIFY_FAILED: 'E_VERIFY_FAILED',
    /** A check returned reasons (revocation, OCSP, name, purpose) or --strict escalated. */
    CHECK_FAILED: 'E_CHECK_FAILED',
    /** Anything else (exit 1). */
    RUNTIME: 'E_RUNTIME',
} as const;

export type ErrorCodeValue = (typeof ErrorCode)[keyof typeof ErrorCode];

/** Every E_* code, in declaration order. */
export const ERROR_CODES: readonly ErrorCodeValue[] = Object.values(ErrorCode);

export type ErrorDetail = Readonly<Record<string, string | number | boolean | null>>;

export interface CliErrorOptions {
    /** pkinative's frozen `PKI_*` code, verbatim. */
    readonly pkiCode?: string;
    /** Code-specific structured detail (limit/configured/observed, offset, path, algorithm). */
    readonly detail?: ErrorDetail;
    /** The CLI flag(s) or command that lift this refusal. */
    readonly remedy?: string;
    /** The PkiReason list of a negative verdict, already in wire form. */
    readonly reasons?: readonly unknown[];
}

/**
 * The one error type commands throw. Exit code 2 is a usage error, 1 any other
 * failure; `code` defaults from the exit code when omitted.
 */
export class CliError extends Error {
    public readonly exitCode: 1 | 2;
    public readonly code: ErrorCodeValue;
    public readonly pkiCode: string | undefined;
    public readonly detail: ErrorDetail | undefined;
    public readonly remedy: string | undefined;
    public readonly reasons: readonly unknown[] | undefined;

    constructor(message: string, exitCode: 1 | 2 = 1, code?: ErrorCodeValue, options: CliErrorOptions = {}) {
        super(message);
        this.name = 'CliError';
        this.exitCode = exitCode;
        this.code = code ?? (exitCode === 2 ? ErrorCode.USAGE : ErrorCode.RUNTIME);
        this.pkiCode = options.pkiCode;
        this.detail = options.detail;
        this.remedy = options.remedy;
        this.reasons = options.reasons;
    }
}

/** Shorthand for a usage error (exit 2, E_USAGE). */
export function usageError(message: string, remedy?: string): CliError {
    return new CliError(message, 2, ErrorCode.USAGE, remedy === undefined ? {} : { remedy });
}
