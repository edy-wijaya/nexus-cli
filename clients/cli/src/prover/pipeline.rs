//! Proving pipeline that orchestrates the full proving process

use std::sync::Arc;

use super::engine::ProvingEngine;
use super::input::InputParser;
use super::types::ProverError;
use crate::analytics::track_verification_failed;
use crate::environment::Environment;
use crate::task::Task;
use nexus_sdk::stwo::seq::Proof;
use sha3::{Digest, Keccak256};
use tokio::task::JoinSet;
use tokio_util::sync::CancellationToken;

/// Orchestrates the complete proving pipeline
pub struct ProvingPipeline;

impl ProvingPipeline {
    /// Execute authenticated proving for a task
    pub async fn prove_authenticated(
        task: &Task,
        environment: &Environment,
        client_id: &str,
        num_workers: &usize,
    ) -> Result<(Vec<Proof>, String, Vec<String>), ProverError> {
        match task.program_id.as_str() {
            "fib_input_initial" => {
                Self::prove_fib_task(task, environment, client_id, num_workers).await
            }
            _ => Err(ProverError::MalformedTask(format!(
                "Unsupported program ID: {}",
                task.program_id
            ))),
        }
    }

    /// Process fibonacci proving task with multiple inputs
    async fn prove_fib_task(
        task: &Task,
        environment: &Environment,
        client_id: &str,
        num_workers: &usize,
    ) -> Result<(Vec<Proof>, String, Vec<String>), ProverError> {
        let all_inputs = task.all_inputs();

        if all_inputs.is_empty() {
            return Err(ProverError::MalformedTask(
                "No inputs provided for task".to_string(),
            ));
        }

        // Create shared references to avoid unnecessary cloning
        let task_shared = Arc::new(task.clone());
        let environment_shared = Arc::new(environment.clone());
        let client_id_shared = Arc::new(client_id.to_string());

        // Create cancellation token for graceful shutdown
        let cancellation_token = CancellationToken::new();

        // Limit the number of concurrent proving jobs to the configured workers
        let concurrency_limit = (*num_workers).max(1);
        let mut pending_inputs = all_inputs.iter().cloned().enumerate();
        let mut join_set: JoinSet<Result<(Proof, String, usize), (usize, ProverError)>> =
            JoinSet::new();

        // Pre-allocate storage for deterministically ordered results
        let total_inputs = all_inputs.len();
        let mut proofs_by_index: Vec<Option<Proof>> = Vec::with_capacity(total_inputs);
        proofs_by_index.resize_with(total_inputs, || None);
        let mut hashes_by_index: Vec<Option<String>> = Vec::with_capacity(total_inputs);
        hashes_by_index.resize_with(total_inputs, || None);
        let mut verification_failures = Vec::new();

        // Helper to spawn a proving job respecting cancellation
        let spawn_job = |join_set: &mut JoinSet<_>, input_index: usize, input_data: Vec<u8>| {
            let task_ref = Arc::clone(&task_shared);
            let environment_ref = Arc::clone(&environment_shared);
            let client_id_ref = Arc::clone(&client_id_shared);
            let cancellation_ref = cancellation_token.clone();

            join_set.spawn(async move {
                if cancellation_ref.is_cancelled() {
                    return Err((
                        input_index,
                        ProverError::MalformedTask("Task cancelled".to_string()),
                    ));
                }

                let inputs =
                    InputParser::parse_triple_input(&input_data).map_err(|e| (input_index, e))?;

                if cancellation_ref.is_cancelled() {
                    return Err((
                        input_index,
                        ProverError::MalformedTask("Task cancelled".to_string()),
                    ));
                }

                let proof = ProvingEngine::prove_and_validate(
                    &inputs,
                    &task_ref,
                    &environment_ref,
                    &client_id_ref,
                )
                .await
                .map_err(|e| (input_index, e))?;

                if cancellation_ref.is_cancelled() {
                    return Err((
                        input_index,
                        ProverError::MalformedTask("Task cancelled".to_string()),
                    ));
                }

                let proof_hash = Self::generate_proof_hash(&proof);

                Ok((proof, proof_hash, input_index))
            });
        };

        // Fill the initial window of concurrent jobs
        for _ in 0..concurrency_limit {
            if let Some((input_index, input_data)) = pending_inputs.next() {
                spawn_job(&mut join_set, input_index, input_data);
            }
        }

        let mut fatal_error: Option<ProverError> = None;

        while let Some(join_result) = join_set.join_next().await {
            match join_result {
                Ok(Ok((proof, proof_hash, input_index))) => {
                    proofs_by_index[input_index] = Some(proof);
                    hashes_by_index[input_index] = Some(proof_hash);
                }
                Ok(Err((input_index, error))) => {
                    if cancellation_token.is_cancelled()
                        && matches!(
                            error,
                            ProverError::MalformedTask(ref msg) if msg == "Task cancelled"
                        )
                    {
                        continue;
                    }

                    match error {
                        ProverError::Stwo(_) | ProverError::GuestProgram(_) => {
                            verification_failures.push((
                                task_shared.clone(),
                                format!("Input {}: {}", input_index, error),
                                environment_shared.clone(),
                                client_id_shared.clone(),
                            ));
                        }
                        other => {
                            cancellation_token.cancel();
                            fatal_error = Some(other);
                            break;
                        }
                    }
                }
                Err(join_error) => {
                    cancellation_token.cancel();
                    fatal_error = Some(ProverError::JoinError(join_error));
                    break;
                }
            }

            if let Some((next_index, next_input)) = pending_inputs.next() {
                spawn_job(&mut join_set, next_index, next_input);
            }
        }

        if fatal_error.is_some() {
            join_set.abort_all();
            while join_set.join_next().await.is_some() {}
            return Err(fatal_error.unwrap());
        }

        // Handle all verification failures in batch (avoid nested spawns)
        let failure_count = verification_failures.len();
        for (task, error_msg, env, client) in verification_failures {
            tokio::spawn(track_verification_failed(
                (*task).clone(),
                error_msg,
                (*env).clone(),
                (*client).clone(),
            ));
        }

        // If we have verification failures, we still return an error
        if failure_count > 0 {
            return Err(ProverError::MalformedTask(format!(
                "{} inputs failed verification",
                failure_count
            )));
        }

        if proofs_by_index.iter().any(|entry| entry.is_none())
            || hashes_by_index.iter().any(|entry| entry.is_none())
        {
            return Err(ProverError::MalformedTask(
                "Incomplete proof results after proving".to_string(),
            ));
        }

        let all_proofs = proofs_by_index
            .into_iter()
            .map(|entry| entry.expect("proof present checked"))
            .collect::<Vec<_>>();
        let proof_hashes = hashes_by_index
            .into_iter()
            .map(|entry| entry.expect("hash present checked"))
            .collect::<Vec<_>>();

        let final_proof_hash = Self::combine_proof_hashes(&task_shared, &proof_hashes);

        Ok((all_proofs, final_proof_hash, proof_hashes))
    }

    /// Generate hash for a proof
    fn generate_proof_hash(proof: &Proof) -> String {
        let proof_bytes = postcard::to_allocvec(proof).expect("Failed to serialize proof");
        format!("{:x}", Keccak256::digest(&proof_bytes))
    }

    /// Combine multiple proof hashes based on task type
    fn combine_proof_hashes(task: &Task, proof_hashes: &[String]) -> String {
        match task.task_type {
            crate::nexus_orchestrator::TaskType::AllProofHashes
            | crate::nexus_orchestrator::TaskType::ProofHash => {
                Task::combine_proof_hashes(proof_hashes)
            }
            _ => proof_hashes.first().cloned().unwrap_or_default(),
        }
    }
}
