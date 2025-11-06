# YAPS — Advanced Process and Container Monitor for Linux and Kubernetes (RKE2)

## Program Description and Capabilities

**YAPS** (Yet Another Process Scanner) — a high-performance CLI utility for monitoring processes and containers on Linux, specifically designed for Kubernetes clusters (especially RKE2/k3s) and virtual/physical servers. The utility provides deep integration with Kubernetes and container environments, identifies process container and pod membership, and supports intelligent filtering and extended output formats (table, JSON, YAML).

### Advantages Compared to Analogues (`top`, `htop`, `glances`, `btop`, etc.)

- **Deep Container Integration:** Unlike classical process monitoring tools, it recognizes Docker, containerd, LXC, systemd-nspawn, and Kubernetes containers via crictl/kubelet.
- **Kubernetes-Aware:** Shows namespace, pod, pod UID, QoS class, container name for each process.
- **Advanced Filtering:** Ability to display only processes from specific namespaces, pods, or containers; filter by users, PIDs, resource conditions.
- **Extended Output:** Large number of output options (CPU, memory, swap, command, user, container, Kubernetes fields).
- **Data Export:** Convenient export in JSON, YAML format for subsequent automated processing and integration with DevOps/Monitoring pipelines.
- **CLI Interface Based on Cobra:** Easy integration into CI/CD, automation, scripts.
- **High Performance:** Project optimized for analyzing large volumes of processes and working under high load.
- **Easy Adaptation in Kubernetes, RKE2, k3s, OpenShift Infrastructure.**

## Building the Application

### Dependencies

- Go 1.19+
- crictl (for Kubernetes integration)
- For Docker: permissions for /var/run/docker.sock (if docker containers are being monitored)

### How to Build

```bash
git clone https://github.com/Sharptop77/yaps.git
cd yaps
go build -o yaps yaps.go
```

## Quick Start and Usage Examples

### Running

```bash
./yaps
```

Will output a detailed table of all processes with container and Kubernetes information (if detected).

### Main Parameters

- `--show-cpu`, `-c` — Show CPU
- `--show-mem`, `-m` — Show memory
- `--show-swap`, `-s` — Show swap
- `--show-cmd`, `-C` — Command line
- `--show-user`, `-u` — User
- `--show-container` — Container process indicator
- `--container-id` — Container ID
- `--container-name` — Container name
- `--show-k8s` — Kubernetes namespace, pod, QoS
- `--k8s-only` — Only processes from Kubernetes pods
- `--k8s-namespace=ns` — Only processes in namespace ns
- `--output table|json|yaml` — Output format
- `--sort-by=field` — Sort by field
- `--cpu-interval=1s` — CPU measurement interval
- `--container-only` — Only container processes
- `--pid`, `--user`, `--set-filter` — Filters by PID, users, resources

### Example Scenarios

- Only processes in Kubernetes namespace:
  ```bash
  ./yaps --k8s-namespace default --show-cpu --show-mem --show-k8s
  ```
- Only container processes:
  ```bash
  ./yaps --container-only --show-container --output json
  ```
- Usage in scripts:
  ```bash
  ./yaps --output json | jq '.[] | select(.cpu_percent > 10.0)'
  ```

### Integration

- Use in cron/systemd to collect metrics on schedule.
- Embed in Ansible, CI/CD pipelines, monitoring systems to get fresh snapshots.
- Export output in JSON/YAML for subsequent visualization or alerting.

### Output Examples

- For Kubernetes processes: fields `k8s_namespace`, `k8s_pod_name`, `k8s_qos_class`
- Processes from docker/containerd/LXC are highlighted separately

### Real-time Monitoring
```bash
# Show top by CPU every 2 seconds
watch -n 2 './yaps -c --cpu-interval 1s --sort-by cpu | head -10'

# Logging activity
while true; do
  echo "$(date): $(./yaps -c -f "cpu>10" --sort-by cpu | head -5)"
  sleep 30
done
```

## 📦 Deployment

### On a Production Server
```bash
# 1. Copy the file
scp yaps.go user@server:/tmp/

# 2. Build on the server
ssh user@server "cd /tmp && go build -o yaps yaps.go"

# 3. Install
ssh user@server "sudo mv /tmp/yaps /usr/local/bin/"
```

### In a Docker Container
```dockerfile
FROM golang:1.21-alpine AS builder
COPY yaps.go /app/
WORKDIR /app
RUN go mod init yaps && \\
    go mod tidy && \\
    go build -o yaps yaps.go

FROM alpine:latest
RUN apk --no-cache add ca-certificates
COPY --from=builder /app/yaps /usr/local/bin/
CMD ["yaps"]
```

### As a systemd Service (for monitoring)
```bash
# Create a service file
sudo tee /etc/systemd/system/yaps.service << EOF
[Unit]
Description=Process Monitor
After=network.target

[Service]
Type=simple
ExecStart=/usr/local/bin/yaps --container-only -r -o json
Restart=always
User=monitoring

[Install]
WantedBy=multi-user.target
EOF

# Start
sudo systemctl enable yaps
sudo systemctl start yaps
```

## 💡 Usage Tips

### For Development
```bash
# Fast iteration
go run yaps.go -c --pid 1-100

# Debug with verbose output
go run yaps.go -r 2>/dev/null  # suppress stderr
```

### For Production Monitoring
```bash
# Compact build
go build -ldflags "-s -w" -o yaps yaps.go

# Binary compression (optional)
upx --best yaps  # if UPX is installed
```

### Integration with Other Tools
```bash
# With jq for JSON analysis
./yaps --container-only -o json | jq '.[] | select(.cpu_percent > 10)'

# With awk for table analysis
./yaps -c | awk 'NR>1 && $3>5 {print $1, $3}' # PID and CPU > 5%

# With curl to send metrics
./yaps -o json | curl -X POST -d @- http://monitoring-server/metrics
```

## 📋 Deployment Checklist

- [ ] Go 1.21+ installed
- [ ] Access to the `/proc` filesystem
- [ ] Read permissions for `/etc/passwd` (for user names)
- [ ] Access to `/var/run/docker.sock` (optional, for container names)
- [ ] Permissions to install to `/usr/local/bin` (for system-wide installation)

## 🎉 Done!

