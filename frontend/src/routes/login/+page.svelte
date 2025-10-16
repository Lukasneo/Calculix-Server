<script lang="ts">
	import { goto } from '$app/navigation';
	import { onMount } from 'svelte';

	let email = '';
	let password = '';
	let loading = false;
	let errorMessage = '';

	async function checkSession() {
		try {
			const response = await fetch('/me', { credentials: 'include' });
			if (response.ok) {
				await goto('/dashboard');
			}
		} catch {
			/* swallowing connectivity errors is fine here */
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

		loading = true;
		try {
			const response = await fetch('/login', {
				method: 'POST',
				headers: { 'Content-Type': 'application/json' },
				credentials: 'include',
				body: JSON.stringify({ email, password })
			});

			if (!response.ok) {
				const payload = await response.json().catch(() => ({}));
				errorMessage = payload?.error ?? 'Invalid email or password.';
				return;
			}

			await goto('/dashboard');
		} catch {
			errorMessage = 'Network error. Please retry in a moment.';
		} finally {
			loading = false;
		}
	}
</script>

<main>
	<h1>Welcome back</h1>
	<p class="description">Sign in to manage your CalculiX simulations.</p>

	<section class="card">
		<form class="form" on:submit|preventDefault={handleSubmit}>
			<label class="form-field">
				<span>Email</span>
				<input type="email" bind:value={email} autocomplete="email" required placeholder="you@example.com" />
			</label>

			<label class="form-field">
				<span>Password</span>
				<input type="password" bind:value={password} autocomplete="current-password" required />
			</label>

			<button class="button" type="submit" disabled={loading}>
				{loading ? 'Signing in…' : 'Sign in'}
			</button>

			{#if errorMessage}
				<p class="message error">{errorMessage}</p>
			{/if}
		</form>

		<p class="muted">
			Need an account?
			<a class="link" href="/register">Create one</a>.
		</p>
	</section>
</main>
