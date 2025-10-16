<script lang="ts">
	import { goto } from '$app/navigation';
	import Navbar from '$lib/components/Navbar.svelte';
	import { apiRequest } from '$lib/api';
	import type { JobEstimatePreview, SessionUser } from '$lib/types';
	import { onDestroy, onMount } from 'svelte';

	type Job = {
		id: string;
		alias: string;
		running: boolean;
		done: boolean;
		cancelled: boolean;
		start_time: string;
		duration_seconds: number;
		element_count: number;
		estimated_runtime_seconds: number;
		benchmark_score: number;
		estimated_credits: number;
		charged_credits: number;
		job_type?: string | null;
		error?: string | null;
	};

	type UploadResponse = {
		id: string;
	};

	const JOB_POLL_INTERVAL = 3000;
	const MAX_ALIAS_LENGTH = 100;

	let user: SessionUser | null = null;
	let jobs: Job[] = [];
	let alias = '';
	let selectedFile: File | null = null;
	let uploading = false;
	let jobActionBusy = false;
	let pollingTimer: ReturnType<typeof setInterval> | undefined;
	let fileInput: HTMLInputElement | null = null;
	let successMessage = '';
	let errorMessage = '';
	let estimate: JobEstimatePreview | null = null;
	let estimateBusy = false;
	let estimateError: string | null = null;
	let estimateRequestId = 0;

	function resetMessages() {
		successMessage = '';
		errorMessage = '';
	}

	function formatDate(value: string) {
		try {
			return new Date(value).toLocaleString();
		} catch {
			return value;
		}
	}

	function formatDuration(seconds?: number | null) {
		const value = Number(seconds ?? 0);
		return value.toFixed(1);
	}

	function formatCredits(amount?: number | null) {
		const value = Number(amount ?? 0);
		return value.toLocaleString(undefined, { maximumFractionDigits: 2 });
	}

	function formatInteger(value?: number | null) {
		return Number(value ?? 0).toLocaleString();
	}

	function displayCredits(value: number, unlimited = false) {
		return unlimited ? 'Unlimited' : formatCredits(value);
	}

	function jobStatusLabel(job: Job) {
		if (job.running) return 'Running';
		if (job.cancelled) return 'Cancelled';
		if (job.error) return 'Failed';
		return 'Done';
	}

	function jobStatusClass(job: Job) {
		if (job.running) return 'status running';
		if (job.cancelled) return 'status cancelled';
		if (job.error) return 'status failed';
		return 'status done';
	}

	async function loadUser() {
		const response = await apiRequest<SessionUser>('profile');

		if (response.status === 0) {
			errorMessage = 'Unable to reach the server. Please retry.';
			return;
		}

		if (!response.ok || !response.data) {
			await goto('/login');
			return;
		}

		user = response.data;

		await fetchJobs();
		startJobPolling();
	}

	async function fetchJobs() {
		const response = await apiRequest<Job[]>('/status', {
			cache: 'no-store'
		});

		if (response.ok && Array.isArray(response.data)) {
			jobs = response.data;
		}
	}

	function startJobPolling() {
		stopJobPolling();
		fetchJobs();
		pollingTimer = setInterval(fetchJobs, JOB_POLL_INTERVAL);
	}

	function stopJobPolling() {
		if (pollingTimer) {
			clearInterval(pollingTimer);
			pollingTimer = undefined;
		}
	}

	function handleFileChange(event: Event) {
		const input = event.currentTarget as HTMLInputElement;
		const [file] = input.files ?? [];
		selectedFile = file ?? null;
		resetMessages();
		if (selectedFile) {
			refreshEstimate();
		} else {
			clearEstimate();
		}
	}

	function clearEstimate() {
		estimateRequestId += 1;
		estimate = null;
		estimateError = null;
		estimateBusy = false;
	}

	async function refreshEstimate() {
		if (!selectedFile || uploading) {
			clearEstimate();
			return;
		}

		const requestId = ++estimateRequestId;
		estimateBusy = true;
		estimateError = null;
		estimate = null;

		const formData = new FormData();
		formData.append('file', selectedFile);

		const response = await apiRequest<JobEstimatePreview>('/jobs/estimate', {
			method: 'POST',
			body: formData
		});

		if (requestId !== estimateRequestId) {
			return;
		}

		estimateBusy = false;

		if (!response.ok || !response.data) {
			estimate = null;
			estimateError = response.error ?? 'Credits konnten nicht geschätzt werden.';
			return;
		}

		estimate = response.data;
	}

	async function submitJob() {
		resetMessages();

		const trimmedAlias = alias.trim();
		if (!trimmedAlias) {
			errorMessage = 'Alias is required.';
			return;
		}

		if (trimmedAlias.length > MAX_ALIAS_LENGTH) {
			errorMessage = `Alias must be at most ${MAX_ALIAS_LENGTH} characters.`;
			return;
		}

		if (!selectedFile) {
			errorMessage = 'Choose a CalculiX .inp file before uploading.';
			return;
		}

		if (!selectedFile.name.toLowerCase().endsWith('.inp')) {
			errorMessage = 'Only .inp files are allowed.';
			return;
		}

	const formData = new FormData();
	formData.append('alias', trimmedAlias);
	formData.append('file', selectedFile);

		uploading = true;

	const response = await apiRequest<UploadResponse>('/upload', {
		method: 'POST',
		body: formData
	});

	if (!response.ok) {
		errorMessage = response.error ?? 'Upload failed. Please try again.';
		uploading = false;
		return;
	}

	const jobId = response.data?.id ?? '(unknown id)';
	const estimateSnapshot = estimate;
	const estimatedCostMessage = estimateSnapshot
		? user?.role === 'admin' || user?.unlimited
			? ' Keine Verrechnung (admin/unlimited).'
			: ` Geschätzte Kosten: ${formatCredits(
				estimateSnapshot.charged_credits
			)} Credits.`
		: '';
	successMessage = `Job ${jobId} submitted successfully.${estimatedCostMessage}`;
	alias = '';
	selectedFile = null;
	if (fileInput) {
		fileInput.value = '';
	}
	await fetchJobs();
	const profileRefresh = await apiRequest<SessionUser>('profile');
	if (profileRefresh.ok && profileRefresh.data) {
		user = profileRefresh.data;
	}
	clearEstimate();
	uploading = false;
}

	async function cancelJob(job: Job) {
		if (jobActionBusy) return;
		jobActionBusy = true;
		resetMessages();

		const response = await apiRequest(`/jobs/${job.id}/cancel`, { method: 'POST' });

		if (!response.ok) {
			errorMessage = response.error ?? 'Failed to cancel the job.';
			jobActionBusy = false;
			return;
		}

		successMessage = `Cancellation requested for job ${job.id}.`;
		await fetchJobs();
		jobActionBusy = false;
	}

	async function deleteJob(job: Job) {
		if (jobActionBusy) return;
		jobActionBusy = true;
		resetMessages();

		const response = await apiRequest(`/jobs/${job.id}`, {
			method: 'DELETE'
		});

		if (!response.ok) {
			errorMessage = response.error ?? 'Failed to delete the job.';
			jobActionBusy = false;
			return;
		}

		successMessage = `Job ${job.id} deleted.`;
		await fetchJobs();
		jobActionBusy = false;
	}

	onMount(() => {
		loadUser();
	});

	onDestroy(() => {
		stopJobPolling();
	});
</script>

<main>
	<Navbar {user} />

	<h1>Simulation dashboard</h1>
	{#if user}
		<p class="description">
			Manage your CalculiX runs as <strong>{user.email}</strong>
			{#if user.role === 'admin'}
				<span class="badge">Admin</span>
			{/if}
		</p>
		<p class="description">
			Credits available:
			<strong>{displayCredits(user.credits, user.unlimited)}</strong>
		</p>
	{/if}

	<div class="toolbar">
		<button class="button ghost" type="button" on:click={fetchJobs}>
			Refresh
		</button>
	</div>

	<section class="card">
		<h2>Start a CalculiX job</h2>
		<p>Pick a unique alias and upload a CalculiX <code>.inp</code> model to launch a new run.</p>

		<form class="upload-controls" on:submit|preventDefault={submitJob}>
			<label class="form-field">
				<span>Alias</span>
				<input
					type="text"
					bind:value={alias}
					maxlength={MAX_ALIAS_LENGTH}
					placeholder="Wing load case A"
					required
				/>
			</label>

			<label class="file-input">
				<span>{selectedFile ? selectedFile.name : 'Drop your model or click to browse'}</span>
				<input
					bind:this={fileInput}
					type="file"
					name="file"
					accept=".inp"
					on:change={handleFileChange}
					aria-label="Upload CalculiX .inp file"
				/>
			</label>

			<div class="actions">
				<button class="button" type="submit" disabled={uploading || !selectedFile}>
					{uploading ? 'Uploading…' : 'Start job'}
				</button>

				{#if estimateBusy}
					<span class="message">Credits werden geschätzt…</span>
				{:else if estimate}
					<span class="message">
						Kreditbedarf:&nbsp;<strong>
							{user?.role === 'admin' || user?.unlimited
								? 'Keine Verrechnung'
								: `${formatCredits(estimate.charged_credits)} Credits`}
						</strong>
						&nbsp;| Laufzeit≈ {formatDuration(estimate.estimated_runtime_seconds)}&nbsp;s · Elemente: {formatInteger(estimate.element_count)}
					</span>
				{:else if estimateError}
					<span class="message error">{estimateError}</span>
				{/if}

				{#if successMessage}
					<span class="message success">{successMessage}</span>
				{/if}

				{#if errorMessage}
					<span class="message error">{errorMessage}</span>
				{/if}
			</div>
		</form>
	</section>

	<section class="card">
		<h2>Jobs</h2>
		{#if jobs.length === 0}
			<p>No jobs have been submitted yet. Upload a model to kick off your first run.</p>
		{:else}
			<table class="jobs-table">
				<thead>
					<tr>
						<th>Alias</th>
						<th>ID &amp; Details</th>
						<th>Status</th>
						<th>Duration&nbsp;(s)</th>
						<th>Credits</th>
						<th>Actions</th>
					</tr>
				</thead>
				<tbody>
					{#each jobs as job}
						<tr>
							<td class="alias-column">
								<strong>{job.alias}</strong>
							</td>
							<td>
								<div class="job-id">{job.id}</div>
								<div class="job-meta">
									<span>Started: {formatDate(job.start_time)}</span>
									{#if job.job_type}
										<span>Type: {job.job_type}</span>
									{/if}
									<span>Est. runtime: {formatDuration(job.estimated_runtime_seconds)} s</span>
									<span>Elements: {formatInteger(job.element_count)}</span>
									<span>Est. credits: {formatCredits(job.estimated_credits)}</span>
									{#if job.error}
										<span class="message error">Error: {job.error}</span>
									{/if}
								</div>
							</td>
							<td>
								<span class={jobStatusClass(job)}>{jobStatusLabel(job)}</span>
							</td>
							<td>{formatDuration(job.duration_seconds)}</td>
							<td>{formatCredits(job.charged_credits)}</td>
							<td class="actions-cell">
								{#if job.running}
									<button
										class="button secondary"
										type="button"
										on:click={() => cancelJob(job)}
										disabled={jobActionBusy}
									>
										{jobActionBusy ? 'Working…' : 'Cancel'}
									</button>
								{:else}
									<div class="row-actions">
										{#if job.done || job.cancelled}
											<a class="download-link" href={`/download/${job.id}`} download>
												Download
											</a>
										{:else}
											<span class="download-link muted">Pending</span>
										{/if}
										<button
											class="button ghost"
											type="button"
											on:click={() => deleteJob(job)}
											disabled={jobActionBusy}
										>
											Delete
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
</main>
