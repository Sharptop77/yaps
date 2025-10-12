# yaps

Yet another ps utility

## 🚀 Quick Installation

### Requirements
- Go 1.21+
- Linux system
- Access to the `/proc` filesystem

### Installation in 3 Commands
```bash
# 1. Download dependencies
go mod download

# 2. Build
go build -o yaps yaps.go

# 3. Run
./yaps
```

## 📁 Single File Advantages

### ✅ Easy Deployment
- One file, `yaps.go`, contains all the code
- Minimal dependencies (only 3 external libraries)
- Fast compilation (~2-3 seconds)
- Easily integrates into existing projects

### ✅ Portability
- Copy `yaps.go` to any Linux machine
- No complex directory structure required
- Works in any directory

### ✅ Easy Modification
- All code in one place
- Simple to add new features
- Convenient debugging


### Basic Functionality
- ✅ PID, PPID of processes
- ✅ CPU utilization with configurable interval (`--cpu-interval`)
- ✅ Memory and swap usage
- ✅ Command lines for processes
- ✅ Users (correctly shows root for UID 0)

### Containers
- ✅ Detection of Docker, LXC, systemd containers
- ✅ Container IDs and names via Docker API
- ✅ Filtering for container-only processes

### Filtering and Sorting
- ✅ Filters by PID, user, resources
- ✅ Sorting by any column
- ✅ Resource filters (`cpu>50`, `memory>1GB`)

### Output Formats
- ✅ Table, JSON, YAML
- ✅ Adaptive columns

## 🎯 Usage Examples

### Basic Commands
```bash
# All processes
./yaps

# CPU monitoring
./yaps -c

# Resources (CPU + memory + swap)
./yaps -r

# Containers
./yaps --container-only --container-name
```

### Advanced Examples
```bash
# Quick CPU diagnostics
./yaps -c --cpu-interval 500ms --sort-by cpu | head -10

# Memory analysis
./yaps -m -f "memory>100MB" --sort-by memory

# JSON output for automation
./yaps --container-only -r -o json > containers.json

# Processes for a specific user
./yaps --user root -r --sort-by cpu
```

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

