use serde_json::Value;
use shared_types::TaskId;

use super::TaskService;
use crate::error::ContextWithErrorCode;
use crate::service::error::ServiceError;

impl TaskService {
    pub async fn run(
        &self,
        task_id: &TaskId,
        params: Option<Value>,
    ) -> Result<Value, ServiceError> {
        let task = self
            .task_provider
            .get_task(task_id)
            .error_while("getting task")?;

        let result = task.run(params).await?;
        tracing::info!("Executed task `{task_id}`");
        Ok(result)
    }
}
