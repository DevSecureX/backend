# Auto-fix Queue System

A comprehensive background queue system for auto-fix functionality to prevent 408 timeouts and provide real-time progress tracking.

## Overview

The auto-fix queue system transforms the synchronous auto-fix process into an asynchronous, queue-based system that provides:

- **Background Processing**: Jobs run asynchronously to prevent timeout errors
- **Real-time Progress**: Users see progress updates during processing
- **Priority Handling**: Jobs are processed based on priority levels
- **Retry Logic**: Failed jobs are automatically retried with exponential backoff
- **Cancellation**: Users can cancel queued jobs
- **Scalability**: Worker scaling based on demand

## Architecture

### Components

1. **AutofixQueueManager** (`manager.py`)
   - Handles job queuing, dequeuing, and status management
   - Uses Redis for queue storage and progress tracking
   - Implements priority-based job processing

2. **AutofixWorker** (`autofix_worker.py`)
   - Background worker that processes auto-fix jobs
   - Integrates with existing `ScanAutoFixer` for actual fix processing
   - Provides progress callbacks and error handling

3. **AutofixWorkerManager** (`worker_manager.py`)
   - Manages multiple auto-fix workers
   - Handles worker lifecycle, scaling, and health monitoring
   - Automatically restarts failed workers

4. **API Endpoints** (in `routes.py`)
   - RESTful API for job management
   - Real-time status and progress endpoints
   - Admin endpoints for worker management

## Queue System Design

### Redis Keys Structure

```
autofix_queue              # Sorted set of queued jobs (priority-based)
autofix_processing:{id}    # Job currently being processed
autofix_progress:{id}      # Real-time progress data
autofix_results:{id}       # Job completion results
autofix_failed             # List of permanently failed jobs
```

### Job States

- `QUEUED`: Job waiting in queue
- `PROCESSING`: Job being processed by worker
- `COMPLETED`: Job completed successfully
- `FAILED`: Job failed permanently (after retries)
- `CANCELLED`: Job cancelled by user

### Priority Levels

- `URGENT` (0): Critical security fixes
- `HIGH` (1): User-initiated auto-fixes
- `NORMAL` (2): Scheduled auto-fixes  
- `LOW` (3): Background maintenance

## API Endpoints

### Job Management

#### Start Async Auto-fix
```http
POST /scans/{scan_id}/auto-fix-async
```

**Parameters:**
- `create_pr`: boolean (default: true) - Create a PR with fixes
- `severity_filter`: array (default: ["critical", "high", "medium"]) - Severities to fix

**Response:**
```json
{
  "status": "queued",
  "job_id": "uuid",
  "scan_id": "uuid", 
  "issues_found": 15,
  "filtered_issues": 8,
  "message": "Auto-fix job queued successfully",
  "estimated_duration": "5-30 minutes"
}
```

#### Get Job Status
```http
GET /scans/autofix-jobs/{job_id}/status
```

**Response:**
```json
{
  "job_id": "uuid",
  "status": "processing",
  "progress": 65,
  "message": "Generating security fixes...",
  "created_at": "2025-01-15T10:30:00Z",
  "started_at": "2025-01-15T10:31:00Z",
  "worker_id": "autofix-worker-1",
  "updated_at": "2025-01-15T10:33:00Z"
}
```

#### Cancel Job
```http
DELETE /scans/autofix-jobs/{job_id}
```

**Response:**
```json
{
  "status": "cancelled",
  "job_id": "uuid",
  "message": "Auto-fix job cancelled successfully"
}
```

#### List User Jobs
```http
GET /scans/autofix-jobs?limit=10
```

**Response:**
```json
{
  "jobs": [
    {
      "job_id": "uuid",
      "scan_id": "uuid",
      "repo_full_name": "user/repo",
      "status": "completed",
      "created_at": "2025-01-15T10:00:00Z",
      "result": {
        "fixed_count": 5,
        "pr_url": "https://github.com/user/repo/pull/123"
      }
    }
  ],
  "total": 1,
  "user_id": 123
}
```

#### Queue Statistics
```http
GET /scans/autofix-queue/stats
```

**Response:**
```json
{
  "queue_stats": {
    "queued": 3,
    "processing": 1,
    "failed": 0,
    "completed_today": 25
  },
  "timestamp": "2025-01-15T10:35:00Z"
}
```

### Worker Management (Admin Only)

#### Worker Status
```http
GET /scans/autofix-workers/status
```

#### Worker Health
```http
GET /scans/autofix-workers/health
```

#### Restart Workers
```http
POST /scans/autofix-workers/restart
```

#### Scale Workers
```http
POST /scans/autofix-workers/scale?worker_count=3
```

## Progress Stages

The system provides detailed progress updates:

1. **0%**: "Initializing auto-fix job..."
2. **10%**: "Validating scan data..."
3. **20%**: "Analyzing security issues..."
4. **30%**: "Filtering issues by severity..."
5. **40%**: "Setting up workspace..."
6. **50%**: "Cloning repository..."
7. **60%**: "Applying security fixes..."
8. **70%**: "Generating security fixes..."
9. **85%**: "Creating pull request..."
10. **95%**: "Finalizing auto-fix..."
11. **100%**: "Auto-fix completed"

## Integration with Existing System

### Updated Auto-fix Endpoint

The existing `/scans/{scan_id}/auto-fix` endpoint now includes a `use_queue` parameter (default: true):

```http
POST /scans/{scan_id}/auto-fix?use_queue=true
```

When `use_queue=true` (default), it redirects to the async system to prevent timeouts.
When `use_queue=false`, it uses the legacy synchronous processing.

### Database Integration

The system reuses the existing `ScanJob` table with `scan_type="autofix"` to distinguish auto-fix jobs from scan jobs.

## Configuration

### Environment Variables

- `AUTOFIX_WORKERS`: Number of auto-fix workers (default: 2 in production, 1 in development)
- `ENABLE_BACKGROUND_WORKERS`: Must be "true" to enable auto-fix workers
- `APP_ENV`: Environment setting (affects worker count and admin access)

### Redis Configuration

The system requires Redis for queue management and progress tracking. It gracefully handles Redis unavailability by falling back to database-only storage.

## Error Handling

### Retry Logic
- **Max Retries**: 2 attempts
- **Retry Delay**: 5 minutes × retry_count (exponential backoff)
- **Timeout**: 30 minutes per job

### Failure Scenarios
- **Authentication Errors**: Token decryption failures, invalid GitHub tokens
- **Repository Errors**: Clone failures, access denied
- **Processing Errors**: AI service failures, PR creation failures
- **System Errors**: Redis unavailability, database connection issues

### Recovery Mechanisms
- **Stale Job Cleanup**: Automatically detects and retries jobs stuck in processing
- **Worker Restart**: Failed workers are automatically restarted
- **Graceful Degradation**: System continues working even if Redis is unavailable

## Frontend Integration

### Polling for Progress

Frontend should poll the job status endpoint every 2-3 seconds:

```javascript
async function pollJobStatus(jobId) {
  const response = await fetch(`/scans/autofix-jobs/${jobId}/status`);
  const status = await response.json();
  
  // Update UI with progress
  updateProgressBar(status.progress, status.message);
  
  if (status.status === 'completed') {
    // Show success with PR link
    showSuccess(status.result);
  } else if (status.status === 'failed') {
    // Show error message
    showError(status.error_message);
  } else if (['queued', 'processing'].includes(status.status)) {
    // Continue polling
    setTimeout(() => pollJobStatus(jobId), 2000);
  }
}
```

### Updated handleAutoFix Function

```javascript
async function handleAutoFix(scanId, createPr = true, severityFilter = ['critical', 'high']) {
  try {
    // Start async auto-fix job
    const response = await fetch(`/scans/${scanId}/auto-fix-async`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        create_pr: createPr,
        severity_filter: severityFilter
      })
    });
    
    const result = await response.json();
    
    if (result.status === 'queued') {
      // Start polling for progress
      pollJobStatus(result.job_id);
      
      // Show initial status
      showJobQueued(result);
    } else {
      showError(result.message);
    }
  } catch (error) {
    showError('Failed to start auto-fix job');
  }
}
```

## Deployment

### Production Checklist

1. **Enable Workers**: Set `ENABLE_BACKGROUND_WORKERS=true`
2. **Redis Configuration**: Ensure Redis is available and configured
3. **Worker Scaling**: Configure appropriate worker count via `AUTOFIX_WORKERS`
4. **Monitoring**: Set up monitoring for queue statistics and worker health
5. **Admin Access**: Ensure admin users have proper permissions for worker management

### Monitoring

Monitor these metrics:
- Queue length (`/scans/autofix-queue/stats`)
- Worker health (`/scans/autofix-workers/health`)
- Job completion rates
- Average processing times
- Error rates

### Scaling

Workers can be dynamically scaled:
- **Scale Up**: During peak usage periods
- **Scale Down**: During low usage to save resources
- **Auto-scaling**: Based on queue length (future enhancement)

## Security Considerations

- **Token Storage**: GitHub tokens are encrypted and only decrypted during processing
- **Admin Endpoints**: Worker management endpoints require admin privileges in production
- **Input Validation**: All job parameters are validated before queuing
- **Resource Limits**: Job timeouts and worker limits prevent resource exhaustion

## Performance

### Optimizations
- **Priority Queue**: High-priority jobs (user-initiated) are processed first
- **Connection Pooling**: Efficient database and Redis connections
- **Progress Batching**: Progress updates are batched to reduce Redis load
- **Memory Management**: Workers are monitored and restarted if memory usage is excessive

### Capacity Planning
- **Throughput**: Each worker can process ~10-20 jobs per hour (depending on repo size)
- **Concurrency**: 2-4 workers recommended for production
- **Queue Capacity**: Redis can handle thousands of queued jobs
- **Storage**: Job results are stored for 24 hours, then cleaned up

## Testing

The system includes comprehensive test coverage:
- **Unit Tests**: Individual component testing
- **Integration Tests**: End-to-end workflow testing  
- **Load Tests**: High-volume job processing
- **Failure Tests**: Error handling and recovery scenarios

Run tests with:
```bash
pytest app/scans/autofix_queue/tests/
```

## Troubleshooting

### Common Issues

1. **Jobs Stuck in Queue**
   - Check worker status: `GET /scans/autofix-workers/health`
   - Restart workers: `POST /scans/autofix-workers/restart`

2. **High Failure Rate**
   - Check GitHub token validity
   - Verify repository access permissions
   - Check OpenAI API key configuration

3. **Slow Processing**
   - Scale up workers: `POST /scans/autofix-workers/scale?worker_count=4`
   - Check Redis performance
   - Monitor system resources

4. **Redis Connection Issues**
   - System gracefully degrades to database-only mode
   - Progress tracking may be limited
   - Check Redis connectivity and configuration

### Debugging

Enable debug logging:
```python
logging.getLogger('app.scans.autofix_queue').setLevel(logging.DEBUG)
```

Check job details:
```bash
# Get job status
curl -H "Authorization: Bearer $TOKEN" \
  "http://localhost:8010/scans/autofix-jobs/$JOB_ID/status"

# Get queue stats  
curl -H "Authorization: Bearer $TOKEN" \
  "http://localhost:8010/scans/autofix-queue/stats"
```

## Future Enhancements

- **Auto-scaling**: Automatic worker scaling based on queue length
- **Job Scheduling**: Delayed job execution for off-peak processing
- **Batch Processing**: Multiple scans in a single auto-fix job
- **Webhook Notifications**: Real-time notifications for job completion
- **Metrics Dashboard**: Comprehensive monitoring and analytics UI
- **Multi-tenant Support**: Resource isolation per organization