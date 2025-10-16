<script lang="ts">
import { goto } from '$app/navigation';
import { apiRequest } from '$lib/api';
import type { AppSettings } from '$lib/types';
	import { onMount } from 'svelte';

	let email = '';
let password = '';
let confirmPassword = '';
let loading = false;
let errorMessage = '';
let allowSignups = true;

async function checkSession() {
	const response = await apiRequest('profile');
	if (response.ok) {
		await goto('/dashboard');
	}
}

async function loadSettings() {
	const response = await apiRequest<AppSettings>('settings');
	if (response.ok && response.data) {
		allowSignups = response.data.allow_signups;
	}
}

onMount(() => {
	checkSession();
	loadSettings();
});

	async function handleSubmit() {
		errorMessage = '';
		if (!email.trim() || !password.trim()) {
			errorMessage = 'Email and password are required.';
			return;
		}

	if (password !== confirmPassword) {
		errorMessage = 'Passwords do not match.';
		return;
	}

	if (!allowSignups) {
		errorMessage = 'Registrations are currently disabled. Please contact an administrator.';
		return;
	}

		loading = true;
		const response = await apiRequest('register', {
			method: 'POST',
			json: { email, password }
		});
		loading = false;

		if (!response.ok) {
			errorMessage = response.error ?? 'Unable to create account.';
			return;
		}

		await goto('/dashboard');
	}
</script>

<main>
	<h1>Create your account</h1>
	<p class="description">Start tracking your CalculiX simulations in one place.</p>

	<section class="card">
		{#if !allowSignups}
			<p class="message error">Registrations are currently disabled by an administrator.</p>
		{/if}

		<form class="form" on:submit|preventDefault={handleSubmit}>
			<label class="form-field">
				<span>Email</span>
				<input
					type="email"
					bind:value={email}
					autocomplete="email"
					required
					placeholder="you@example.com"
					disabled={!allowSignups}
				/>
			</label>

			<label class="form-field">
				<span>Password</span>
				<input
					type="password"
					bind:value={password}
					autocomplete="new-password"
					required
					disabled={!allowSignups}
				/>
			</label>

			<label class="form-field">
				<span>Confirm Password</span>
				<input
					type="password"
					bind:value={confirmPassword}
					autocomplete="new-password"
					required
					disabled={!allowSignups}
				/>
			</label>

			<button class="button" type="submit" disabled={loading || !allowSignups}>
				{#if loading}
					Creating account…
				{:else if !allowSignups}
					Registrations disabled
				{:else}
					Create account
				{/if}
			</button>

			{#if errorMessage}
				<p class="message error">{errorMessage}</p>
			{/if}
		</form>

		<p class="muted">
			Already have an account?
			<a class="link" href="/login">Sign in</a>.
		</p>
	</section>
</main>
