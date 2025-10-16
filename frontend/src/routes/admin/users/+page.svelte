<script lang="ts">
	import { goto } from '$app/navigation';
	import Navbar from '$lib/components/Navbar.svelte';
	import { apiRequest } from '$lib/api';
	import type {
		AdminUser,
		AppSettings,
		BenchmarkStatus,
		SessionUser,
		UserCredits
	} from '$lib/types';
	import { onMount } from 'svelte';

let user: SessionUser | null = null;
let users: AdminUser[] = [];
let loading = true;
let settings: AppSettings | null = null;
let settingsBusy = false;
let benchmark: BenchmarkStatus | null = null;
let benchmarkLoading = true;
let benchmarkBusy = false;

	type ToastKind = 'success' | 'error';
	let toast: { kind: ToastKind; message: string } | null = null;
	let toastTimer: ReturnType<typeof setTimeout> | null = null;

	let rowBusy = new Set<number>();

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

	function setRowBusy(id: number, busy: boolean) {
		const next = new Set(rowBusy);
		if (busy) {
			next.add(id);
		} else {
			next.delete(id);
		}
		rowBusy = next;
	}

	function isRowBusy(id: number) {
		return rowBusy.has(id);
	}

	function formatDate(value: string) {
		try {
			return new Date(value).toLocaleString();
		} catch {
			return value;
		}
	}

	function formatCredits(value: number) {
		return value.toLocaleString(undefined, { maximumFractionDigits: 2 });
	}

	function formatBenchmark(value: number | null | undefined) {
		if (value == null) {
			return 'Not recorded yet.';
		}
		return `${value.toFixed(3)} s`;
	}

	async function loadData() {
		const profileResponse = await apiRequest<SessionUser>('profile');
		if (!profileResponse.ok || !profileResponse.data) {
			await goto('/login');
			return;
		}

		user = profileResponse.data;
		if (user.role !== 'admin') {
			await goto('/');
			return;
		}

		await fetchUsers();
		await fetchSettings();
		await fetchBenchmark();
		loading = false;
	}

async function fetchUsers() {
	const response = await apiRequest<AdminUser[]>('admin/users');
	if (!response.ok || !Array.isArray(response.data)) {
		setToast('error', response.error ?? 'Failed to load users.');
		users = [];
		return;
	}

	users = response.data;
}

async function fetchSettings() {
	const response = await apiRequest<AppSettings>('admin/settings');
	if (!response.ok || !response.data) {
		setToast('error', response.error ?? 'Failed to load registration settings.');
		settings = null;
		return;
	}

	settings = response.data;
}

async function fetchBenchmark() {
	benchmarkLoading = true;
	const response = await apiRequest<BenchmarkStatus>('admin/benchmark');
	benchmarkLoading = false;

	if (!response.ok || !response.data) {
		setToast('error', response.error ?? 'Failed to load benchmark status.');
		benchmark = null;
		return;
	}

	benchmark = response.data;
}

async function toggleSignups() {
	if (!settings) return;
	clearToast();
	settingsBusy = true;
	const response = await apiRequest<AppSettings>('admin/settings', {
		method: 'POST',
		json: { allow_signups: !settings.allow_signups }
	});
	settingsBusy = false;

	if (!response.ok || !response.data) {
		setToast('error', response.error ?? 'Failed to update registration setting.');
		return;
	}

	settings = response.data;
	setToast(
		'success',
		settings.allow_signups
			? 'Sign ups enabled for new users.'
			: 'Sign ups disabled. New registrations are blocked.'
	);
}

	async function adjustCredits(target: AdminUser) {
		clearToast();
	const current = target.unlimited ? 'unlimited' : formatCredits(target.credits);
	const input = prompt(
		`Set credits for ${target.email} (enter "unlimited" für unbegrenzte Credits)`,
		current
	);
	if (input === null) {
		return;
	}

	const trimmed = input.trim().toLowerCase();
	const unlimited = trimmed === 'unlimited';
	let parsed = Number(input);
	if (!unlimited) {
		if (!Number.isFinite(parsed) || parsed < 0) {
			setToast('error', 'Enter a non-negative number for credits oder "unlimited".');
			return;
		}
	}

	setRowBusy(target.id, true);
	const body = unlimited
		? { unlimited: true }
		: { credits: parsed, unlimited: false };
	const response = await apiRequest<UserCredits>(`admin/users/${target.id}/credits`, {
		method: 'POST',
		json: body
	});
		setRowBusy(target.id, false);

		if (!response.ok || !response.data) {
			setToast('error', response.error ?? 'Failed to update credits.');
			return;
		}

	const payload = response.data;

	users = users.map((item) =>
		item.id === target.id
			? { ...item, credits: payload.credits, unlimited: payload.unlimited }
			: item
	);

	setToast(
		'success',
		payload.unlimited
			? `Credits für ${target.email} sind jetzt unbegrenzt.`
			: `Credits for ${target.email} set to ${formatCredits(payload.credits)}.`
	);
}

async function runBenchmark() {
	clearToast();
	benchmarkBusy = true;
	const response = await apiRequest<BenchmarkStatus>('admin/benchmark/run', {
		method: 'POST'
	});
	benchmarkBusy = false;

	if (!response.ok || !response.data) {
		setToast('error', response.error ?? 'Benchmark failed to execute.');
		return;
	}

	benchmark = response.data;

	const measured = response.data.score_seconds;
	setToast(
		'success',
		measured != null
			? `Benchmark completed in ${measured.toFixed(3)} seconds.`
			: 'Benchmark completed.'
	);
}

async function toggleActive(target: AdminUser) {
		clearToast();
		setRowBusy(target.id, true);

		const response = await apiRequest<AdminUser>(`admin/users/${target.id}/toggle_active`, {
			method: 'POST'
		});

		setRowBusy(target.id, false);

		if (!response.ok || !response.data) {
			setToast('error', response.error ?? 'Failed to update user status.');
			return;
		}

		users = users.map((item) => (item.id === target.id ? response.data! : item));

		setToast(
			'success',
			response.data.active
				? `${response.data.email} reactivated.`
				: `${response.data.email} deactivated.`
		);
	}

	async function deleteUser(target: AdminUser) {
		clearToast();
		if (
			!confirm(
				`Delete ${target.email}? This removes the account and all associated simulations. This action cannot be undone.`
			)
		) {
			return;
		}

		setRowBusy(target.id, true);
		const response = await apiRequest(`admin/users/${target.id}`, {
			method: 'DELETE'
		});
		setRowBusy(target.id, false);

		if (!response.ok) {
			setToast('error', response.error ?? 'Failed to delete user.');
			return;
		}

		users = users.filter((item) => item.id !== target.id);
		setToast('success', `${target.email} deleted.`);
	}

	onMount(() => {
		loadData();
	});
</script>

<main>
	<Navbar {user} />

	<h1>Admin users</h1>

	{#if toast}
		<div class={`toast ${toast.kind}`}>
			{toast.message}
		</div>
	{/if}

	{#if loading}
		<p class="description">Loading user directory…</p>
	{:else}
		<section class="card">
			<h2>Registration</h2>
			{#if !settings}
				<p>Loading registration settings…</p>
			{:else}
				<p>
					Public sign ups are currently
					<strong>{settings.allow_signups ? 'enabled' : 'disabled'}</strong>.
				</p>
				<button class="button ghost" type="button" on:click={toggleSignups} disabled={settingsBusy}>
					{#if settingsBusy}
						Saving…
					{:else if settings.allow_signups}
						Disable sign ups
					{:else}
						Enable sign ups
					{/if}
				</button>
			{/if}
		</section>

		<section class="card">
			<h2>Benchmark</h2>
			{#if benchmarkLoading}
				<p>Loading benchmark status…</p>
			{:else}
				<p>
					Latest score:
					{#if benchmark && benchmark.score_seconds != null}
						<strong>{formatBenchmark(benchmark.score_seconds)}</strong>
					{:else}
						<em>No benchmark run yet.</em>
					{/if}
				</p>
				{#if benchmark && benchmark.recorded_at}
					<p class="description">
						Last run {formatDate(benchmark.recorded_at)}
					</p>
				{/if}
				<button
					class="button primary"
					type="button"
					on:click={runBenchmark}
					disabled={benchmarkBusy}
				>
					{benchmarkBusy ? 'Running…' : 'Run Benchmark'}
				</button>
			{/if}
		</section>

		<section class="card">
			<h2>Accounts</h2>
			<p>Review all users, toggle access, or remove accounts entirely.</p>

					{#if users.length === 0}
						<p>No users available.</p>
					{:else}
						<table class="users-table">
					<thead>
						<tr>
							<th>Email</th>
							<th>Role</th>
							<th>Status</th>
							<th>Credits</th>
							<th>Created</th>
							<th>Actions</th>
						</tr>
					</thead>
					<tbody>
						{#each users as entry}
							<tr>
								<td class="email-column">
									<strong>{entry.email}</strong>
								</td>
								<td>
									<span class="badge">{entry.role === 'admin' ? 'Admin' : 'User'}</span>
								</td>
								<td>
									<span class={entry.active ? 'status done' : 'status cancelled'}>
										{entry.active ? 'Active' : 'Deactivated'}
									</span>
								</td>
								<td>
									{#if entry.unlimited}
										<span class="badge">Unlimited</span>
									{:else}
										{formatCredits(entry.credits)}
									{/if}
								</td>
								<td>{formatDate(entry.created_at)}</td>
								<td class="actions-cell">
									{#if user && user.id === entry.id}
										<span class="muted">This is your account</span>
									{:else}
										<div class="row-actions">
											<button
												class="button ghost"
												type="button"
												on:click={() => adjustCredits(entry)}
												disabled={isRowBusy(entry.id)}
											>
												{isRowBusy(entry.id) ? 'Updating…' : 'Set credits'}
											</button>
											<button
												class="button ghost"
												type="button"
												on:click={() => toggleActive(entry)}
												disabled={isRowBusy(entry.id)}
											>
												{entry.active
													? isRowBusy(entry.id)
														? 'Updating…'
														: 'Deactivate'
													: isRowBusy(entry.id)
														? 'Updating…'
														: 'Activate'}
											</button>
											<button
												class="button secondary"
												type="button"
												on:click={() => deleteUser(entry)}
												disabled={isRowBusy(entry.id)}
											>
												{isRowBusy(entry.id) ? 'Deleting…' : 'Delete'}
											</button>
										</div>
									{/if}
								</td>
							</tr>
						{/each}
					</tbody>
				</table>
			{/if}
		</section>
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

	.users-table {
		width: 100%;
		border-collapse: collapse;
	}

	.users-table th {
		text-align: left;
		font-size: 14px;
		text-transform: uppercase;
		letter-spacing: 0.08em;
		color: #94a3b8;
		font-weight: 600;
		padding-bottom: 12px;
	}

	.users-table td {
		padding: 14px 0;
		border-top: 1px solid rgba(226, 232, 240, 0.9);
		color: #1f2937;
	}

	.email-column {
		min-width: 240px;
	}
</style>
