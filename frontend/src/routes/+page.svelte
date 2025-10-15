<script>
	import { onDestroy, onMount } from 'svelte';

	const POLL_INTERVAL = 3000;

	let jobs = [];
	let selectedFile = null;
	let uploading = false;
	let errorMessage = '';
	let successMessage = '';
	let pollingTimer;
	let fileInput;
	let actionBusy = false;

	function resetMessages() {
		errorMessage = '';
		successMessage = '';
	}

	async function fetchJobs() {
		try {
			const response = await fetch('/status', { cache: 'no-store' });
			if (!response.ok) return;
			const payload = await response.json();
			if (Array.isArray(payload)) {
				jobs = payload;
			}
		} catch (error) {
			console.error('Failed to refresh jobs', error);
		}
	}

	onMount(() => {
		fetchJobs();
		pollingTimer = setInterval(fetchJobs, POLL_INTERVAL);

		return () => {
			if (pollingTimer) {
				clearInterval(pollingTimer);
			}
		};
	});

	onDestroy(() => {
		if (pollingTimer) {
			clearInterval(pollingTimer);
		}
	});

	function handleFileChange(event) {
		const [file] = event.currentTarget.files ?? [];
		selectedFile = file ?? null;
		resetMessages();
	}

	function statusLabel(job) {
		if (job.running) return 'Running';
		if (job.cancelled) return 'Cancelled';
		if (job.error) return 'Failed';
		return 'Done';
	}

	function statusClass(job) {
		if (job.running) return 'status running';
		if (job.cancelled) return 'status cancelled';
		if (job.error) return 'status failed';
		return 'status done';
	}

	function formatDuration(seconds) {
		const value = Number(seconds ?? 0);
		return value.toFixed(1);
	}

	function formatDate(value) {
		try {
			return new Date(value).toLocaleString();
		} catch {
			return value;
		}
	}

	async function submitJob() {
		if (!selectedFile) {
			errorMessage = 'Choose a CalculiX .inp file before uploading.';
			return;
		}

		if (!selectedFile.name.toLowerCase().endsWith('.inp')) {
			errorMessage = 'Only .inp files are allowed.';
			return;
		}

		const formData = new FormData();
		formData.append('file', selectedFile);

		uploading = true;
		resetMessages();

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
			selectedFile = null;
			if (fileInput) {
				fileInput.value = '';
			}
			await fetchJobs();
		} catch (error) {
			console.error('Upload failed', error);
			errorMessage = 'Network error while uploading. Please retry.';
		} finally {
			uploading = false;
		}
	}

	async function cancelJob(job) {
		if (actionBusy) return;
		actionBusy = true;
		resetMessages();

		try {
			const response = await fetch(`/jobs/${job.id}/cancel`, { method: 'POST' });
			const payload = await response.json().catch(() => ({}));

			if (!response.ok) {
				const message = payload?.error ?? 'Failed to cancel the job.';
				errorMessage = message;
				return;
			}

			successMessage = `Cancellation requested for job ${job.id}.`;
			await fetchJobs();
		} catch (error) {
			console.error('Cancel job failed', error);
			errorMessage = 'Network error while cancelling. Please retry.';
		} finally {
			actionBusy = false;
		}
	}

	async function deleteJob(job) {
		if (actionBusy) return;
		actionBusy = true;
		resetMessages();

		try {
			const response = await fetch(`/jobs/${job.id}`, { method: 'DELETE' });
			if (!response.ok) {
				let message = 'Failed to delete the job.';
				try {
					const payload = await response.json();
					message = payload?.error ?? message;
				} catch {
					// swallow JSON errors
				}
				errorMessage = message;
				return;
			}

			successMessage = `Job ${job.id} deleted.`;
			await fetchJobs();
		} catch (error) {
			console.error('Delete job failed', error);
			errorMessage = 'Network error while deleting. Please retry.';
		} finally {
			actionBusy = false;
		}
	}
</script>

<main>
	<h1>CalculiX Server</h1>
	<p class="description">
		Upload CalculiX <code>.inp</code> models, run them on the server and monitor their progress in real-time.
	</p>

	<section class="card">
		<h2>Upload a model</h2>
		<p>Select a CalculiX input file to start a new job. Each upload runs inside an isolated job directory.</p>

		<form class="upload-controls" on:submit|preventDefault={submitJob}>
			<label class="file-input">
				<span>{selectedFile ? selectedFile.name : 'Drop your model or click to browse'}</span>
				<input
					bind:this={fileInput}
					type="file"
					accept=".inp"
					on:change={handleFileChange}
					aria-label="Upload CalculiX .inp file"
				/>
			</label>

			<div class="actions">
				<button class="button" type="submit" disabled={uploading || !selectedFile || actionBusy}>
					{uploading ? 'Uploading…' : 'Start Job'}
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
						<th>ID &amp; Details</th>
						<th>Status</th>
						<th>Duration&nbsp;(s)</th>
						<th>Actions</th>
					</tr>
				</thead>
				<tbody>
					{#each jobs as job}
						<tr>
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
								<span class={statusClass(job)}>{statusLabel(job)}</span>
							</td>
							<td>{formatDuration(job.duration_seconds)}</td>
							<td class="actions-cell">
								{#if job.running}
									<button
										class="button secondary"
										type="button"
										on:click|preventDefault={() => cancelJob(job)}
										disabled={actionBusy}
									>
										{actionBusy ? 'Working…' : 'Cancel'}
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
											on:click|preventDefault={() => deleteJob(job)}
											disabled={actionBusy}
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
