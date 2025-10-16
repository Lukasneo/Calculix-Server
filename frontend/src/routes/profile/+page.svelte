<script lang="ts">
	import { goto } from '$app/navigation';
	import Navbar from '$lib/components/Navbar.svelte';
	import { apiRequest } from '$lib/api';
	import type { SessionUser } from '$lib/types';
	import { onMount } from 'svelte';

	const EMAIL_REGEX = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
	const PASSWORD_MIN_LENGTH = 8;

	let user: SessionUser | null = null;
	let loading = true;

	let emailBusy = false;
	let passwordBusy = false;

	let emailForm = {
		newEmail: ''
	};

	let passwordForm = {
		oldPassword: '',
		newPassword: '',
		confirmPassword: ''
	};

	type ToastKind = 'success' | 'error';
	let toast: { kind: ToastKind; message: string } | null = null;
	let toastTimer: ReturnType<typeof setTimeout> | null = null;

	function setToast(kind: ToastKind, message: string) {
		toast = { kind, message };
		if (toastTimer) {
			clearTimeout(toastTimer);
		}
		toastTimer = setTimeout(() => {
			toast = null;
			toastTimer = null;
		}, 4000);
	}

	function clearToast() {
		if (toastTimer) {
			clearTimeout(toastTimer);
			toastTimer = null;
		}
		toast = null;
	}

	async function loadProfile() {
		const response = await apiRequest<SessionUser>('profile');

		if (response.status === 0) {
			setToast('error', 'Unable to reach the server. Please retry shortly.');
			loading = false;
			return;
		}

		if (!response.ok || !response.data) {
			await goto('/login');
			return;
		}

		user = response.data;
		emailForm.newEmail = user.email;
		loading = false;
	}

	async function submitEmailUpdate() {
		clearToast();

		const currentEmail = user?.email ?? '';
		const nextEmail = emailForm.newEmail.trim().toLowerCase();

		if (!EMAIL_REGEX.test(nextEmail)) {
			setToast('error', 'Enter a valid email address.');
			return;
		}

		if (nextEmail === currentEmail) {
			setToast('error', 'That is already your current email.');
			return;
		}

		emailBusy = true;
		const response = await apiRequest<SessionUser>('profile/update_email', {
			method: 'POST',
			json: { new_email: nextEmail }
		});
		emailBusy = false;

		if (!response.ok || !response.data) {
			setToast('error', response.error ?? 'Failed to update email. Please try again.');
			return;
		}

		user = response.data;
		emailForm.newEmail = user.email;
		setToast('success', 'Email updated successfully.');
	}

	async function submitPasswordUpdate() {
		clearToast();

		const { oldPassword, newPassword, confirmPassword } = passwordForm;

		if (!oldPassword.trim() || !newPassword.trim()) {
			setToast('error', 'Both current and new passwords are required.');
			return;
		}

		if (newPassword !== confirmPassword) {
			setToast('error', 'New password confirmation does not match.');
			return;
		}

		if (newPassword.length < PASSWORD_MIN_LENGTH) {
			setToast('error', `Password must be at least ${PASSWORD_MIN_LENGTH} characters long.`);
			return;
		}

		if (oldPassword === newPassword) {
			setToast('error', 'Choose a new password that differs from the current one.');
			return;
		}

		passwordBusy = true;
		const response = await apiRequest('profile/update_password', {
			method: 'POST',
			json: {
				old_password: oldPassword,
				new_password: newPassword
			}
		});
		passwordBusy = false;

		if (!response.ok) {
			setToast('error', response.error ?? 'Failed to update password. Please try again.');
			return;
		}

		passwordForm = {
			oldPassword: '',
			newPassword: '',
			confirmPassword: ''
		};
		setToast('success', 'Password updated successfully.');
	}

	onMount(() => {
		loadProfile();
	});
</script>

<main>
	<Navbar {user} />

	<h1>Your profile</h1>

	{#if toast}
		<div class={`toast ${toast.kind}`}>
			{toast.message}
		</div>
	{/if}

	{#if loading}
		<p class="description">Loading your profile…</p>
	{:else if user}
		<p class="description">
			Email: <strong>{user.email}</strong>
			<span class="badge">{user.role === 'admin' ? 'Admin' : 'User'}</span>
		</p>

		<section class="card">
			<h2>Update email</h2>
			<p>Change the sign-in email associated with your account.</p>

			<form
				class="form"
				on:submit|preventDefault={submitEmailUpdate}
			>
				<label class="form-field">
					<span>New email</span>
					<input
						type="email"
						bind:value={emailForm.newEmail}
						placeholder="you@example.com"
						required
					/>
				</label>
				<div class="actions">
					<button class="button" type="submit" disabled={emailBusy}>
						{emailBusy ? 'Updating…' : 'Update email'}
					</button>
				</div>
			</form>
		</section>

		<section class="card">
			<h2>Change password</h2>
			<p>Use a strong password containing letters, numbers, and symbols.</p>

			<form
				class="form"
				on:submit|preventDefault={submitPasswordUpdate}
			>
				<label class="form-field">
					<span>Current password</span>
					<input
						type="password"
						bind:value={passwordForm.oldPassword}
						autocomplete="current-password"
						required
					/>
				</label>

				<label class="form-field">
					<span>New password</span>
					<input
						type="password"
						bind:value={passwordForm.newPassword}
						autocomplete="new-password"
						minlength={PASSWORD_MIN_LENGTH}
						required
					/>
				</label>

				<label class="form-field">
					<span>Confirm new password</span>
					<input
						type="password"
						bind:value={passwordForm.confirmPassword}
						autocomplete="new-password"
						required
					/>
				</label>

				<div class="actions">
					<button class="button" type="submit" disabled={passwordBusy}>
						{passwordBusy ? 'Updating…' : 'Update password'}
					</button>
				</div>
			</form>
		</section>
	{:else}
		<p class="description">We could not load your profile. Please reload the page.</p>
	{/if}
</main>

<style>
	.toast {
		margin-bottom: 24px;
		padding: 12px 18px;
		border-radius: 12px;
		font-weight: 600;
	}

	.toast.success {
		background: rgba(16, 185, 129, 0.18);
		color: #0f766e;
	}

	.toast.error {
		background: rgba(248, 113, 113, 0.2);
		color: #b91c1c;
	}
</style>
