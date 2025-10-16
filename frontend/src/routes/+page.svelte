<script lang="ts">
	import { goto } from '$app/navigation';
	import { onMount } from 'svelte';

	onMount(() => {
		goto('/dashboard');
	});
</script>

<main>
	<h1>CalculiX Simulation Platform</h1>
	<p class="description">Redirecting to your dashboard…</p>
	<p>
		If nothing happens, <a class="link" href="/login">log in</a> or
		<a class="link" href="/register">create an account</a>.
	</p>
</main>
