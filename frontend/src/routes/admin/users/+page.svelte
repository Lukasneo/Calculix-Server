<script lang="ts">
	import { goto } from '$app/navigation';
	import Navbar from '$lib/components/Navbar.svelte';
	import { apiRequest } from '$lib/api';
	import type {
		AdminUser,
		AppSettings,
		BenchmarkStatus,
		SessionUser,
		MailLogEntry,
		SmtpSettings,
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

type SmtpDraft = {
	host: string;
	port: string;
	username: string;
	password: string;
	from_address: string;
	use_tls: boolean;
};

function createEmptySmtpDraft(): SmtpDraft {
	return {
		host: '',
		port: '587',
		username: '',
		password: '',
		from_address: '',
		use_tls: true
	};
}

let smtpDraft: SmtpDraft = createEmptySmtpDraft();
let smtpLoading = true;
let smtpBusy = false;
let smtpTestBusy = false;
let mailBaseUrl = '';
let mailLog: MailLogEntry[] = [];
let mailLogLoading = true;
let mailLogError: string | null = null;

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

	function applySmtpConfig(config: SmtpSettings) {
		smtpDraft = {
			host: config.host ?? '',
			port: String(config.port ?? 587),
			username: config.username ?? '',
			password: config.password ?? '',
			from_address: config.from_address ?? '',
			use_tls: config.use_tls ?? true
		};
	}

	function prepareSmtpPayload(): SmtpSettings | null {
		const host = smtpDraft.host.trim();
		const fromAddress = smtpDraft.from_address.trim();
		const portValue = Number(smtpDraft.port);

		if (!host) {
			setToast('error', 'SMTP host is required.');
			return null;
		}

		if (!Number.isInteger(portValue) || portValue <= 0 || portValue > 65535) {
			setToast('error', 'SMTP port must be between 1 and 65535.');
			return null;
		}

		if (!fromAddress) {
			setToast('error', 'SMTP from address is required.');
			return null;
		}

		const username = smtpDraft.username.trim();
		const password = smtpDraft.password.trim();

		return {
			host,
			port: portValue,
			username: username ? username : null,
			password: password ? password : null,
			from_address: fromAddress,
			use_tls: smtpDraft.use_tls
		};
	}

	async function fetchSmtpConfig() {
		smtpLoading = true;
		const response = await apiRequest<SmtpSettings>('admin/smtp');
		smtpLoading = false;

		if (!response.ok || !response.data) {
			setToast('error', response.error ?? 'Failed to load mail settings.');
			smtpDraft = createEmptySmtpDraft();
			return;
		}

		applySmtpConfig(response.data);
	}

async function persistSmtpConfig(options: { announceSuccess?: boolean } = {}) {
	const { announceSuccess = true } = options;
	const payload = prepareSmtpPayload();
	if (!payload) {
		return null;
	}

		smtpBusy = true;
		const response = await apiRequest<SmtpSettings>('admin/smtp/save', {
			method: 'POST',
			json: payload
		});
		smtpBusy = false;

		if (!response.ok || !response.data) {
			setToast('error', response.error ?? 'Failed to save mail settings.');
			return null;
		}

		applySmtpConfig(response.data);
		if (announceSuccess) {
			setToast('success', 'Mail settings updated.');
		}
	return response.data;
}

async function persistMailBaseUrl() {
	const trimmed = mailBaseUrl.trim();
	const response = await apiRequest<AppSettings>('admin/settings', {
		method: 'POST',
		json: { mail_base_url: trimmed }
	});

	if (!response.ok || !response.data) {
		setToast('error', response.error ?? 'Failed to update base URL.');
		return null;
	}

	settings = response.data;
	mailBaseUrl = response.data.mail_base_url ?? '';
	return response.data;
}

async function saveSmtpSettings() {
	clearToast();
	const savedConfig = await persistSmtpConfig({ announceSuccess: false });
	if (!savedConfig) {
		return;
	}

	const updatedSettings = await persistMailBaseUrl();
	if (!updatedSettings) {
		return;
	}

	setToast('success', 'Mail settings updated.');
}

async function sendSmtpTestEmail() {
	clearToast();
	const saved = await persistSmtpConfig({ announceSuccess: false });
	if (!saved) {
		return;
	}

	const updatedSettings = await persistMailBaseUrl();
	if (!updatedSettings) {
		return;
	}

	smtpTestBusy = true;
	const response = await apiRequest('admin/smtp/test', {
			method: 'POST',
			parseJson: false
		});
		smtpTestBusy = false;

		if (!response.ok) {
			setToast('error', response.error ?? 'Failed to send test email.');
			return;
		}

		setToast('success', 'Test email sent to your admin address.');
	}

	async function fetchMailLog(options: { silent?: boolean } = {}) {
		const { silent = false } = options;
		mailLogLoading = true;
		mailLogError = null;
		const response = await apiRequest<MailLogEntry[]>('admin/mail/log');
		mailLogLoading = false;

		if (!response.ok || !Array.isArray(response.data)) {
			mailLog = [];
			mailLogError = response.error ?? 'Failed to load mail log.';
			if (!silent) {
				setToast('error', mailLogError);
			}
			return;
		}

		mailLog = response.data;
	}

	async function refreshMailLog() {
		clearToast();
		await fetchMailLog();
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
		await fetchSmtpConfig();
		await fetchMailLog({ silent: true });
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
		mailBaseUrl = '';
		return;
	}

	settings = response.data;
	mailBaseUrl = response.data.mail_base_url ?? '';
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
	mailBaseUrl = response.data.mail_base_url ?? '';
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
			<h2>Mail Settings</h2>
			<p>Configure the SMTP server used to send notifications and test the connection.</p>
			{#if smtpLoading}
				<p>Loading mail settings…</p>
			{:else}
				<div class="mail-form">
					<div class="input-group">
						<label for="smtp-host">SMTP host</label>
						<input
							id="smtp-host"
							type="text"
							placeholder="smtp.example.com"
							bind:value={smtpDraft.host}
							autocapitalize="off"
							autocomplete="off"
						/>
					</div>
					<div class="input-group">
						<label for="smtp-port">Port</label>
						<input
							id="smtp-port"
							type="text"
							inputmode="numeric"
							pattern="[0-9]*"
							placeholder="587"
							bind:value={smtpDraft.port}
						/>
					</div>
					<div class="input-group">
						<label for="smtp-username">Username</label>
						<input
							id="smtp-username"
							type="text"
							placeholder="Optional"
							bind:value={smtpDraft.username}
							autocapitalize="off"
							autocomplete="off"
						/>
					</div>
					<div class="input-group">
						<label for="smtp-password">Password</label>
						<input
							id="smtp-password"
							type="password"
							placeholder="Optional"
							bind:value={smtpDraft.password}
							autocomplete="off"
						/>
					</div>
				<div class="input-group full-width">
					<label for="smtp-from">From address</label>
					<input
						id="smtp-from"
						type="email"
						placeholder="no-reply@example.com"
						bind:value={smtpDraft.from_address}
						autocapitalize="off"
					/>
				</div>
				<div class="input-group full-width">
					<label for="mail-base-url">Public base URL</label>
					<input
						id="mail-base-url"
						type="text"
						placeholder="https://your-domain.com"
						bind:value={mailBaseUrl}
						autocapitalize="off"
					/>
					<p class="field-hint">
						Used for links in notification emails. Include protocol, e.g. <code>https://example.com</code>.
					</p>
				</div>
				<div class="checkbox-group">
					<label>
						<input type="checkbox" bind:checked={smtpDraft.use_tls} />
						<span>Use TLS</span>
					</label>
					</div>
					<div class="actions-row">
						<button
							type="button"
							class="button primary"
							on:click={saveSmtpSettings}
							disabled={smtpBusy || smtpTestBusy}
						>
							{smtpBusy ? 'Saving…' : 'Save Mail Settings'}
						</button>
						<button
							type="button"
							class="button ghost"
							on:click={sendSmtpTestEmail}
							disabled={smtpBusy || smtpTestBusy}
						>
							{smtpTestBusy ? 'Sending test…' : 'Send Test Email'}
						</button>
					</div>
				</div>
			{/if}
		</section>

		<section class="card">
			<h2>Mail Activity</h2>
			<p>Latest 20 email attempts with their delivery status.</p>
			<div class="mail-log-actions">
				<button type="button" class="button ghost" on:click={refreshMailLog} disabled={mailLogLoading}>
					{mailLogLoading ? 'Refreshing…' : 'Refresh'}
				</button>
			</div>
			{#if mailLogLoading}
				<p>Loading mail log…</p>
			{:else if mailLog.length === 0}
				<p>No email activity recorded yet.</p>
			{:else}
				<table class="mail-log-table">
					<thead>
						<tr>
							<th>Time</th>
							<th>Recipient</th>
							<th>Subject</th>
							<th>Template</th>
							<th>Status</th>
							<th>Error</th>
						</tr>
					</thead>
					<tbody>
						{#each mailLog as entry}
							<tr>
								<td>{formatDate(entry.timestamp)}</td>
								<td>{entry.to}</td>
								<td>{entry.subject}</td>
								<td>{entry.template}</td>
								<td>
									<span class={entry.status === 'sent' ? 'status done' : 'status failed'}>
										{entry.status === 'sent' ? 'Sent' : 'Failed'}
									</span>
								</td>
								<td>
									{#if entry.error}
										<span class="error-text">{entry.error}</span>
									{:else}
										<span class="muted">—</span>
									{/if}
								</td>
							</tr>
						{/each}
					</tbody>
				</table>
			{/if}
			{#if mailLogError}
				<p class="error-text">{mailLogError}</p>
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

	.mail-form {
		display: grid;
		gap: 16px;
		grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
	}

	.mail-form .input-group {
		display: flex;
		flex-direction: column;
		gap: 6px;
	}

	.field-hint {
		margin: 0;
		color: #64748b;
		font-size: 13px;
	}

	.mail-form .input-group.full-width {
		grid-column: 1 / -1;
	}

	.mail-form .checkbox-group {
		grid-column: 1 / -1;
		display: flex;
		align-items: center;
		gap: 12px;
	}

	.mail-form .checkbox-group label {
		display: flex;
		align-items: center;
		gap: 8px;
		font-weight: 600;
		color: #1f2937;
	}

	.mail-form .actions-row {
		grid-column: 1 / -1;
		display: flex;
		gap: 12px;
		flex-wrap: wrap;
	}

	.mail-log-actions {
		display: flex;
		justify-content: flex-end;
		margin-bottom: 12px;
	}

	.mail-log-table {
		width: 100%;
		border-collapse: collapse;
	}

	.mail-log-table th {
		text-align: left;
		font-size: 13px;
		letter-spacing: 0.05em;
		text-transform: uppercase;
		color: #94a3b8;
		padding-bottom: 8px;
	}

	.mail-log-table td {
		padding: 10px 0;
		border-top: 1px solid rgba(226, 232, 240, 0.8);
		color: #1f2937;
		font-size: 14px;
	}

	.error-text {
		color: #b91c1c;
		font-weight: 600;
	}

	.muted {
		color: #94a3b8;
		font-size: 13px;
	}
</style>
