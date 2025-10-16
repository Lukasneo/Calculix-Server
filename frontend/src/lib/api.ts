type JsonValue = Record<string, unknown> | unknown[] | string | number | boolean | null;

const DEV_DEFAULT_ORIGIN = import.meta.env.DEV ? 'http://127.0.0.1:8080' : '';
const RAW_BACKEND_ORIGIN =
	(import.meta.env.VITE_BACKEND_ORIGIN as string | undefined) ?? DEV_DEFAULT_ORIGIN;
const BACKEND_ORIGIN = (RAW_BACKEND_ORIGIN ?? '').replace(/\/+$/, '');

const RAW_API_PREFIX = (import.meta.env.VITE_API_PREFIX as string | undefined) ?? '/api';
const NORMALIZED_PREFIX = RAW_API_PREFIX.replace(/\/+$/, '');

const API_BASE =
	NORMALIZED_PREFIX.startsWith('http://') || NORMALIZED_PREFIX.startsWith('https://')
		? NORMALIZED_PREFIX.replace(/\/+$/, '')
		: (() => {
				if (!NORMALIZED_PREFIX) {
					return BACKEND_ORIGIN;
				}
				const prefixed = NORMALIZED_PREFIX.startsWith('/')
					? NORMALIZED_PREFIX
					: `/${NORMALIZED_PREFIX}`;
				return `${BACKEND_ORIGIN}${prefixed}`;
			})();

const EFFECTIVE_API_PREFIX =
	API_BASE || (NORMALIZED_PREFIX ? (NORMALIZED_PREFIX.startsWith('/') ? NORMALIZED_PREFIX : `/${NORMALIZED_PREFIX}`) : '/api');

export interface ApiRequestOptions extends RequestInit {
	json?: JsonValue;
	parseJson?: boolean;
}

export interface ApiResponse<T> {
	ok: boolean;
	status: number;
	data?: T;
	error?: string;
	raw?: Response;
}

function resolvePath(path: string): string {
	if (!path) return EFFECTIVE_API_PREFIX;
	if (path.startsWith('http://') || path.startsWith('https://')) {
		return path;
	}

	const origin = BACKEND_ORIGIN.replace(/\/+$/, '');

	if (path.startsWith('/')) {
		if (!origin) {
			return path;
		}
		return `${origin}${path}`;
	}

	const base = EFFECTIVE_API_PREFIX.replace(/\/+$/, '');
	const segment = path.replace(/^\/+/, '');

	if (!base) {
		return `/${segment}`;
	}

	return `${base}/${segment}`;
}

export async function apiRequest<T = unknown>(
	path: string,
	options: ApiRequestOptions = {}
): Promise<ApiResponse<T>> {
	const { json, parseJson = true, headers: customHeaders, ...rest } = options;
	const headers = new Headers(customHeaders ?? {});

	let body = rest.body;

	if (json !== undefined) {
		if (!(body instanceof FormData)) {
			if (!headers.has('Content-Type')) {
				headers.set('Content-Type', 'application/json');
			}
			body = JSON.stringify(json);
		}
	}

	const target = resolvePath(path);

	let response: Response;
	try {
		response = await fetch(target, {
			credentials: 'include',
			...rest,
			headers,
			body
		});
	} catch (error) {
		return {
			ok: false,
			status: 0,
			error: error instanceof Error ? error.message : 'Network request failed'
		};
	}

	let data: T | undefined;
	if (parseJson) {
		const contentType = response.headers.get('content-type') ?? '';
		if (contentType.includes('application/json') && response.status !== 204) {
			try {
				data = (await response.json()) as T;
			} catch {
				data = undefined;
			}
		}
	}

	let errorMessage: string | undefined;
	if (!response.ok) {
		let payloadError: string | undefined;
		if (data && typeof data === 'object') {
			const record = data as Record<string, unknown>;
			const rawError = record.error;
			if (typeof rawError === 'string') {
				payloadError = rawError;
			} else if (rawError != null) {
				payloadError = String(rawError);
			}
		}

		const statusText = response.statusText || '';
		errorMessage = payloadError ?? (statusText || 'Request failed');
	}

	return {
		ok: response.ok,
		status: response.status,
		data,
		error: errorMessage,
		raw: response
	};
}
