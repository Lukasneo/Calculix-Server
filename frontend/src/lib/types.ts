export type UserRole = 'user' | 'admin';

export interface SessionUser {
	id: number;
	email: string;
	role: UserRole;
	active: boolean;
}

export interface AdminUser extends SessionUser {
	created_at: string;
}

export interface AppSettings {
	allow_signups: boolean;
}
