<script lang="ts">
	import { goto } from '$app/navigation';
	import { onDestroy, onMount } from 'svelte';

	type User = {
		id: number;
		email: string;
		role: 'user' | 'admin';
		created_at: string;
	};

	type Job = {
		id: string;
		alias: string;
		running: boolean;
		done: boolean;
		cancelled: boolean;
		start_time: string;
		duration_seconds: number;
		job_type?: string | null;
		error?: string | null;
	};

	const JOB_POLL_INTERVAL = 3000;
	const MAX_ALIAS_LENGTH = 100;

	let user: User | null = null;
	let jobs: Job[] = [];
	let alias = '';
	let selectedFile: File | null = null;
	let uploading = false;
	let jobActionBusy = false;
	let pollingTimer: ReturnType<typeof setInterval> | undefined;
	let fileInput: HTMLInputElement | null = null;
	let successMessage = '';
	let errorMessage = '';

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
		try {
			const response = await fetch('/me', { credentials: 'include' });
			if (!response.ok) {
				await goto('/login');
				return;
			}
			user = await response.json();
		} catch {
			errorMessage = 'Unable to reach the server. Please retry.';
			return;
		}

		await fetchJobs();
		startJobPolling();
	}

	async function fetchJobs() {
		try {
			const response = await fetch('/status', {
				cache: 'no-store'
			});
			if (!response.ok) return;

			const payload = await response.json();
			if (Array.isArray(payload)) {
				jobs = payload;
			}
		} catch {
			// ignore polling errors; table will refresh next time
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

		try {
			const response = await fetch('/upload', {
				method: 'POST',
				body: formData
			});

			const payload = await response.json().catch(() => ({}));

			if (!response.ok) {
				errorMessage = payload?.error ?? 'Upload failed. Please try again.';
				return;
			}

			const jobId = payload?.id ?? '(unknown id)';
			successMessage = `Job ${jobId} submitted successfully.`;
			alias = '';
			selectedFile = null;
			if (fileInput) {
				fileInput.value = '';
			}
			await fetchJobs();
		} catch {
			errorMessage = 'Network error while uploading. Please retry.';
		} finally {
			uploading = false;
		}
	}

	async function cancelJob(job: Job) {
		if (jobActionBusy) return;
		jobActionBusy = true;
		resetMessages();

		try {
			const response = await fetch(`/jobs/${job.id}/cancel`, { method: 'POST' });
			const payload = await response.json().catch(() => ({}));

			if (!response.ok) {
				errorMessage = payload?.error ?? 'Failed to cancel the job.';
				return;
			}

			successMessage = `Cancellation requested for job ${job.id}.`;
			await fetchJobs();
		} catch {
			errorMessage = 'Network error while cancelling. Please retry.';
		} finally {
			jobActionBusy = false;
		}
	}

	async function deleteJob(job: Job) {
		if (jobActionBusy) return;
		jobActionBusy = true;
		resetMessages();

		try {
			const response = await fetch(`/jobs/${job.id}`, { method: 'DELETE' });
			if (!response.ok) {
				let message = 'Failed to delete the job.';
				try {
					const payload = await response.json();
					message = payload?.error ?? message;
				} catch {
					// ignore
				}
				errorMessage = message;
				return;
			}

			successMessage = `Job ${job.id} deleted.`;
			await fetchJobs();
		} catch {
			errorMessage = 'Network error while deleting. Please retry.';
		} finally {
			jobActionBusy = false;
		}
	}

	async function handleLogout() {
		try {
			await fetch('/logout', { method: 'POST', credentials: 'include' });
		} catch {
			/* ignore */
		}
		await goto('/login');
	}

	onMount(() => {
		loadUser();
	});

	onDestroy(() => {
		stopJobPolling();
	});
</script>

<main>
	<h1>Simulation dashboard</h1>
	{#if user}
		<p class="description">
			Signed in as <strong>{user.email}</strong>
			{#if user.role === 'admin'}
				<span class="badge">Admin</span>
			{/if}
		</p>
	{/if}

	<div class="toolbar">
		<button class="button ghost" type="button" on:click={fetchJobs}>
			Refresh
		</button>
		<button class="button secondary" type="button" on:click={handleLogout}>
			Log out
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
									{#if job.error}
										<span class="message error">Error: {job.error}</span>
									{/if}
								</div>
							</td>
							<td>
								<span class={jobStatusClass(job)}>{jobStatusLabel(job)}</span>
							</td>
							<td>{formatDuration(job.duration_seconds)}</td>
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
