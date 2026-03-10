# syz-agent 

`syz-agent` is an AI agent running as part of the continuous fuzzing infrastructure. It continuously polls the `syz-cluster` dashboard for tasks and executes agentic workflows.

## Running Locally with Docker

You can easily run `syz-agent` locally without Kubernetes. This is the best approach for testing and development.

1. Build the Docker image from the root of the syzkaller repository:
   ```bash
   docker build -t syz-agent:local -f syz-agent/Dockerfile .
   ```

2. Prepare a configuration file (e.g. `config.json`):
   ```json
   {
       "http": ":8080",
       "dashboard_client": "my-local-agent",
       "dashboard_addr": "https://syzkaller.appspot.com",
       "dashboard_key": "YOUR_KEY",
       "model": "gemini-3.1-pro",
       "mcp": true
   }
   ```

3. Run the container, mounting your configuration file:
   ```bash
   docker run -it --rm \
       -p 8080:8080 \
       -v $(pwd)/config.json:/etc/syz-agent/config.json:ro \
       syz-agent:local -config=/etc/syz-agent/config.json
   ```
   *Note: `pkg/updater` is bypassed inside Docker because the `-syzkaller=/syzkaller` flag is passed via the Dockerfile's ENTRYPOINT. `syz-agent` will use the pre-built binaries inside the container.*


