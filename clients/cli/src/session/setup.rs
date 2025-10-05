//! Session setup and initialization

use crate::analytics::set_wallet_address_for_reporting;
use crate::config::Config;
use crate::environment::Environment;
use crate::events::Event;
use crate::orchestrator::OrchestratorClient;
use crate::runtime::start_authenticated_worker;
use ed25519_dalek::SigningKey;
use std::error::Error;
use sysinfo::System;
use tokio::sync::{broadcast, mpsc};
use tokio::task::JoinHandle;

/// Session data for both TUI and headless modes
#[derive(Debug)]
pub struct SessionData {
    /// Event receiver for worker events
    pub event_receiver: mpsc::Receiver<Event>,
    /// Join handles for worker tasks
    pub join_handles: Vec<JoinHandle<()>>,
    /// Shutdown sender to stop all workers
    pub shutdown_sender: broadcast::Sender<()>,
    /// Shutdown sender for max tasks completion
    pub max_tasks_shutdown_sender: broadcast::Sender<()>,
    /// Node ID
    pub node_id: u64,
    /// Orchestrator client
    pub orchestrator: OrchestratorClient,
    /// Number of workers (for display purposes)
    pub num_workers: usize,
}

/// Warn the user if their available memory seems insufficient for the task(s) at hand
pub fn warn_memory_configuration(thread_count: usize, available_memory_bytes: Option<u64>) {
    if thread_count == 0 {
        return;
    }

    if let Some(available_bytes) = available_memory_bytes {
        let Some(usable_budget_bytes) = usable_memory_budget_bytes(available_bytes) else {
            return;
        };

        let required_bytes = (thread_count as u128)
            * (crate::consts::cli_consts::PROJECTED_MEMORY_REQUIREMENT as u128);

        if required_bytes > usable_budget_bytes {
            let gib = 1024_f64.powi(3);
            let required_gib = required_bytes as f64 / gib;
            let usable_gib = usable_budget_bytes as f64 / gib;
            let available_gib = available_bytes as f64 / gib;

            crate::print_cmd_warn!(
                "OOM warning",
                "Estimated memory usage (~{:.1} GiB) for {} thread(s) exceeds the configured safe memory budget (~{:.1} GiB of ~{:.1} GiB total). If proving fails due to an out-of-memory error, please restart the Nexus CLI with a smaller value supplied to `--max-threads`.",
                required_gib,
                thread_count,
                usable_gib,
                available_gib
            );
            std::thread::sleep(std::time::Duration::from_secs(3));
        }
    }
}

/// Sets up an authenticated worker session
///
/// This function handles all the common setup required for both TUI and headless modes:
/// 1. Creates signing key for the prover
/// 2. Sets up shutdown channel
/// 3. Starts authenticated worker
/// 4. Returns session data for mode-specific handling
///
/// # Arguments
/// * `config` - Resolved configuration with node_id and client_id
/// * `env` - Environment to connect to
/// * `max_threads` - Optional maximum number of threads for proving
/// * `max_difficulty` - Optional override for task difficulty
///
/// # Returns
/// * `Ok(SessionData)` - Successfully set up session
/// * `Err` - Session setup failed
pub async fn setup_session(
    config: Config,
    env: Environment,
    check_mem: bool,
    max_threads: Option<u32>,
    max_tasks: Option<u32>,
    max_difficulty: Option<crate::nexus_orchestrator::TaskDifficulty>,
) -> Result<SessionData, Box<dyn Error>> {
    let node_id = config.node_id.parse::<u64>()?;
    let client_id = config.user_id;

    // Create a signing key for the prover
    let mut csprng = rand_core::OsRng;
    let signing_key: SigningKey = SigningKey::generate(&mut csprng);

    // Create orchestrator client
    let orchestrator_client = OrchestratorClient::new(env.clone());

    let available_memory_bytes = system_available_memory_bytes();
    let safe_memory_budget_bytes = available_memory_bytes.and_then(usable_memory_budget_bytes);
    let hardware_threads = std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(1_usize);
    let memory_limited_threads = safe_memory_budget_bytes.map(threads_supported_by_budget);

    let auto_threads = memory_limited_threads
        .map(|limit| limit.min(hardware_threads))
        .unwrap_or(hardware_threads)
        .max(1);

    let num_workers: usize = max_threads
        .map(|threads| threads.max(1) as usize)
        .unwrap_or(auto_threads);

    if max_threads.is_none() {
        let memory_message = if let (Some(limit), Some(budget_bytes), Some(available_bytes)) = (
            memory_limited_threads,
            safe_memory_budget_bytes,
            available_memory_bytes,
        ) {
            let gib = 1024_f64.powi(3);
            let safe_gib = budget_bytes as f64 / gib;
            let available_gib = available_bytes as f64 / gib;
            format!(
                "memory budget (~{safe_gib:.1} GiB of ~{available_gib:.1} GiB total) suggests up to {limit} thread(s)"
            )
        } else {
            "memory estimate unavailable".to_string()
        };
        crate::print_cmd_info!(
            "Worker configuration",
            "Auto-selected {num_workers} prover worker(s) based on {hardware_threads} detected CPU thread(s); {memory_message}."
        );
    }

    // Warn the user if the memory demands of their configuration is risky
    if check_mem {
        warn_memory_configuration(num_workers, available_memory_bytes);
    }
    // Create shutdown channel - only one shutdown signal needed
    let (shutdown_sender, _) = broadcast::channel(1);

    // Set wallet for reporting
    set_wallet_address_for_reporting(config.wallet_address.clone());

    // Start authenticated worker (only mode we support now)
    let (event_receiver, join_handles, max_tasks_shutdown_sender) = start_authenticated_worker(
        node_id,
        signing_key,
        orchestrator_client.clone(),
        shutdown_sender.subscribe(),
        env,
        client_id,
        max_tasks,
        num_workers,
        max_difficulty,
    )
    .await;

    Ok(SessionData {
        event_receiver,
        join_handles,
        shutdown_sender,
        max_tasks_shutdown_sender,
        node_id,
        orchestrator: orchestrator_client,
        num_workers,
    })
}

fn system_available_memory_bytes() -> Option<u64> {
    let mut system = System::new();
    system.refresh_memory();
    let available_kib = system.available_memory();
    if available_kib == 0 {
        None
    } else {
        available_kib.checked_mul(1024)
    }
}

fn usable_memory_budget_bytes(available_bytes: u64) -> Option<u128> {
    let utilization_percent = crate::consts::cli_consts::MEMORY_UTILIZATION_PERCENT as u128;
    if utilization_percent == 0 {
        return None;
    }

    let available_bytes = available_bytes as u128;
    if available_bytes == 0 {
        return None;
    }

    let usable_bytes = available_bytes.saturating_mul(utilization_percent) / 100;

    if usable_bytes == 0 {
        None
    } else {
        Some(usable_bytes)
    }
}

fn threads_supported_by_budget(budget_bytes: u128) -> usize {
    let per_thread_requirement = crate::consts::cli_consts::PROJECTED_MEMORY_REQUIREMENT as u128;
    if per_thread_requirement == 0 {
        return 1;
    }

    let limit = (budget_bytes / per_thread_requirement) as usize;
    limit.max(1)
}
