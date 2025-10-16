export type UserRole = 'user' | 'admin';

export interface SessionUser {
	id: number;
	email: string;
	role: UserRole;
	active: boolean;
	credits: number;
	unlimited: boolean;
}

export interface AdminUser extends SessionUser {
	created_at: string;
}

export interface AppSettings {
	allow_signups: boolean;
}

export interface UserCredits {
	id: number;
	email: string;
	credits: number;
	unlimited: boolean;
}

export interface BenchmarkStatus {
	score_seconds: number | null;
	recorded_at: string | null;
}

export interface JobEstimatePreview {
	estimated_credits: number;
	estimated_runtime_seconds: number;
	element_count: number;
	benchmark_score: number;
	charged_credits: number;
}
