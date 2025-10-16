<script lang="ts">
	import { goto } from '$app/navigation';
	import { onMount } from 'svelte';

	let email = '';
	let password = '';
	let confirmPassword = '';
	let loading = false;
	let errorMessage = '';

	async function checkSession() {
		try {
			const response = await fetch('/me', { credentials: 'include' });
			if (response.ok) {
				await goto('/dashboard');
			}
		} catch {
			/* ignore network errors */
		}
	}

	onMount(() => {
		checkSession();
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

		loading = true;
		try {
			const response = await fetch('/register', {
				method: 'POST',
				headers: { 'Content-Type': 'application/json' },
				credentials: 'include',
				body: JSON.stringify({ email, password })
			});

			if (!response.ok) {
				const payload = await response.json().catch(() => ({}));
				errorMessage = payload?.error ?? 'Unable to create account.';
				return;
			}

			await goto('/dashboard');
		} catch {
			errorMessage = 'Network error. Please retry.';
		} finally {
			loading = false;
		}
	}
</script>

<main>
	<h1>Create your account</h1>
	<p class="description">Start tracking your CalculiX simulations in one place.</p>

	<section class="card">
		<form class="form" on:submit|preventDefault={handleSubmit}>
			<label class="form-field">
				<span>Email</span>
				<input type="email" bind:value={email} autocomplete="email" required placeholder="you@example.com" />
			</label>

			<label class="form-field">
				<span>Password</span>
				<input type="password" bind:value={password} autocomplete="new-password" required />
			</label>

			<label class="form-field">
				<span>Confirm Password</span>
				<input type="password" bind:value={confirmPassword} autocomplete="new-password" required />
			</label>

			<button class="button" type="submit" disabled={loading}>
				{loading ? 'Creating account…' : 'Create account'}
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
