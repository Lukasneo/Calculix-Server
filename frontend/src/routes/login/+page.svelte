<script lang="ts">
	import { goto } from '$app/navigation';
	import { apiRequest } from '$lib/api';
	import { onMount } from 'svelte';

	let email = '';
	let password = '';
	let loading = false;
	let errorMessage = '';

	async function checkSession() {
		const response = await apiRequest('profile');
		if (response.ok) {
			await goto('/dashboard');
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
		const response = await apiRequest('login', {
			method: 'POST',
			json: { email, password }
		});
		loading = false;

		if (!response.ok) {
			errorMessage = response.error ?? 'Invalid email or password.';
			return;
		}

		await goto('/dashboard');
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
