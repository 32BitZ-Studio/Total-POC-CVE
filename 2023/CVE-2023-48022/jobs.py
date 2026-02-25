from ray.job_submission import JobSubmissionClient, JobStatus
import time

# If using a remote cluster, replace 127.0.0.1 with the head node’s IP address.
Client = JobSubmissionClient("http://192.168.241.37:9000")
job_id = Client.submit_job(
# Entrypoint shell command to execute
entrypoint="python3 malicious.py",
# Path to the local directory that contains the script.py file
runtime_env={"working_dir": "./"}
)
print(job_id)

def wait_until_status(job_id, status_to_wait_for, timeout_seconds=5):
    start = time.time()
    while time.time() - start <= timeout_seconds:
        status = Client.get_job_status(job_id)
        print(f"status: {status}")
        if status in status_to_wait_for:
            break
        time.sleep(1)


wait_until_status(job_id, {JobStatus.SUCCEEDED, JobStatus.STOPPED, JobStatus.FAILED})
logs = Client.get_job_logs(job_id)
print(logs)
