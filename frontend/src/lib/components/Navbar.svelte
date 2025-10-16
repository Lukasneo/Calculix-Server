<script lang="ts">
	import { goto } from '$app/navigation';
	import { page } from '$app/stores';
	import { apiRequest } from '$lib/api';
	import type { SessionUser } from '$lib/types';

	export let user: SessionUser | null = null;

	const navItems = [
		{ href: '/dashboard', label: 'Dashboard', when: () => true },
		{ href: '/profile', label: 'Profile', when: (current: SessionUser | null) => Boolean(current) },
		{
			href: '/admin/users',
			label: 'Admin Panel',
			when: (current: SessionUser | null) => current?.role === 'admin'
		}
	] as const;

	let isLoggingOut = false;

	async function handleLogout() {
		if (isLoggingOut || !user) return;
		isLoggingOut = true;
		await apiRequest('logout', { method: 'POST' });
		await goto('/login');
		isLoggingOut = false;
	}
</script>

<nav class="navbar">
	<div class="nav-start">
		<a class="brand" href="/dashboard">CalculiX</a>
		<div class="links">
			{#each navItems as item}
				{#if item.when(user)}
					<a
						class:selected={$page.url.pathname.startsWith(item.href)}
						href={item.href}
					>
						{item.label}
					</a>
				{/if}
			{/each}
		</div>
	</div>
	<div class="nav-end">
		{#if user}
			<span class="user-email">{user.email}</span>
			<button class="button ghost" type="button" on:click={handleLogout} disabled={isLoggingOut}>
				{isLoggingOut ? 'Logging out…' : 'Log out'}
			</button>
		{:else}
			<a class="button ghost" href="/login">Log in</a>
		{/if}
	</div>
</nav>

<style>
	.navbar {
		display: flex;
		align-items: center;
		justify-content: space-between;
		padding: 12px 0 32px 0;
		gap: 16px;
		flex-wrap: wrap;
	}

	.nav-start {
		display: flex;
		align-items: center;
		gap: 20px;
		flex-wrap: wrap;
	}

	.brand {
		font-weight: 700;
		font-size: 22px;
		color: #1f2937;
		text-decoration: none;
	}

	.links {
		display: flex;
		gap: 12px;
		flex-wrap: wrap;
	}

	.links a {
		font-weight: 600;
		color: #475569;
		text-decoration: none;
		padding: 6px 16px;
		border-radius: 999px;
		transition: background 0.2s ease, color 0.2s ease;
	}

	.links a:hover {
		background: rgba(37, 99, 235, 0.08);
		color: #1d4ed8;
	}

	.links a.selected {
		background: rgba(37, 99, 235, 0.15);
		color: #1d4ed8;
	}

	.nav-end {
		display: flex;
		align-items: center;
		gap: 12px;
	}

	.user-email {
		font-size: 14px;
		font-weight: 600;
		color: #475569;
	}

	.button.ghost {
		padding: 10px 20px;
	}
</style>
