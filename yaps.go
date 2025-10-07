// go:build linux
package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
//	"path/filepath"
	"strconv"
	"strings"
//	"syscall"
	"time"

	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"
)

type Options struct {
	ShowCPU        bool
	ShowMem        bool
	ShowSwap       bool
	ShowCmd        bool
	ShowUser       bool
	ShowContainer  bool
	ShowContainerID   bool
	ShowContainerName bool

	Output         string // table|json|yaml
	Resources      bool
	ContainerOnly  bool
	PIDsExpr       string
	UserExpr       string

	UseDocker      bool
	NoTrunc        bool
	Threads        int
}

type ProcInfo struct {
	PID            int
	PPID           int
	CPUPercent     float64
	RSSKiB         int64
	SwapKiB        int64
	Cmdline        string
	User           string
	InContainer    bool
	ContainerID    string
	ContainerName  string
}

func main() {
	opts := &Options{}
	var rootCmd = &cobra.Command{
		Use:   "psgo",
		Short: "Process lister with container awareness",
		RunE: func(cmd *cobra.Command, args []string) error {
			if opts.Resources {
				opts.ShowCPU, opts.ShowMem, opts.ShowSwap = true, true, true
			}
			if opts.Output == "" {
				opts.Output = "table"
			}
			if err := run(opts); err != nil {
				return err
			}
			return nil
		},
	}
	rootCmd.Flags().BoolVarP(&opts.ShowCPU, "show-cpu", "c", false, "Show CPU")
	rootCmd.Flags().BoolVarP(&opts.ShowMem, "show-mem", "m", false, "Show memory (RSS)")
	rootCmd.Flags().BoolVarP(&opts.ShowSwap, "show-swap", "s", false, "Show swap")
	rootCmd.Flags().BoolVarP(&opts.Resources, "resources", "r", false, "Show CPU, memory, swap")
	rootCmd.Flags().BoolVarP(&opts.ShowCmd, "show-cmd", "C", false, "Show command line")
	rootCmd.Flags().BoolVarP(&opts.ShowUser, "show-user", "u", false, "Show user")
	rootCmd.Flags().BoolVar(&opts.ShowContainer, "show-container", false, "Show container flag")
	rootCmd.Flags().BoolVar(&opts.ShowContainerID, "container-id", false, "Show container ID")
	rootCmd.Flags().BoolVar(&opts.ShowContainerName, "container-name", false, "Show container name via Docker")
	rootCmd.Flags().StringVarP(&opts.Output, "output", "o", "table", "Output format: table|json|yaml")
	rootCmd.Flags().BoolVar(&opts.ContainerOnly, "container-only", false, "Only processes in containers")
	rootCmd.Flags().StringVar(&opts.PIDsExpr, "pid", "", "PID filter: N or N-M or comma list")
	rootCmd.Flags().StringVar(&opts.UserExpr, "user", "", "User filter: name or uid")
	rootCmd.Flags().BoolVar(&opts.UseDocker, "docker", false, "Use Docker API to resolve container names")
	rootCmd.Flags().BoolVar(&opts.NoTrunc, "no-trunc", false, "Do not truncate long fields")
	rootCmd.Flags().IntVar(&opts.Threads, "threads", 4, "Parallel readers")

	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run(opts *Options) error {
	uptimeSec, err := readUptime()
	if err != nil {
		return fmt.Errorf("read uptime: %w", err)
	}
	hz, err := clockTicks()
	if err != nil {
		// fallback to 100 if sysconf fails
		hz = 100
	}

	uidToName, _ := loadPasswd()

	pidAllow := buildPIDSet(opts.PIDsExpr)
	_, userIsUID, _ := parseUserExpr(opts.UserExpr, uidToName)

	pids, err := listPIDs()
	if err != nil {
		return err
	}

	results := make([]ProcInfo, 0, len(pids))
	for _, pid := range pids {
		if len(pidAllow) > 0 && !pidAllow[pid] {
			continue
		}
		pi, ok := collectForPID(pid, uptimeSec, hz, uidToName)
		if !ok {
			continue
		}
		// user filter
		if opts.UserExpr != "" {
			if userIsUID {
				if pi.User != opts.UserExpr {
					continue
				}
			} else {
				// pi.User может быть UID строкой при отсутствии имени
				if pi.User != opts.UserExpr {
					continue
				}
			}
		}
		// container filters
		if opts.ContainerOnly && !pi.InContainer {
			continue
		}
		// docker name resolve
		if opts.UseDocker && pi.ContainerID != "" && opts.ShowContainerName {
			if name, err := dockerNameByID(pi.ContainerID); err == nil && name != "" {
				pi.ContainerName = strings.TrimPrefix(name, "/")
			}
		}
		results = append(results, pi)
	}

	switch strings.ToLower(opts.Output) {
	case "json":
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(filterFields(results, opts))
	case "yaml":
		out := filterFields(results, opts)
		enc := yaml.NewEncoder(os.Stdout)
		defer enc.Close()
		return enc.Encode(out)
	case "table":
		printTable(filterFields(results, opts), opts)
		return nil
	default:
		return fmt.Errorf("unknown output: %s", opts.Output)
	}
}

func listPIDs() ([]int, error) {
	dir, err := os.ReadDir("/proc")
	if err != nil {
		return nil, err
	}
	res := make([]int, 0, len(dir))
	for _, de := range dir {
		if !de.IsDir() {
			continue
		}
		name := de.Name()
		if name[0] < '0' || name[0] > '9' {
			continue
		}
		if pid, err := strconv.Atoi(name); err == nil {
			res = append(res, pid)
		}
	}
	return res, nil
}

func collectForPID(pid int, uptimeSec float64, hz int64, uidToName map[uint32]string) (ProcInfo, bool) {
	var pi ProcInfo
	pi.PID = pid

	statPath := fmt.Sprintf("/proc/%d/stat", pid)
	stContent, err := os.ReadFile(statPath)
	if err != nil {
		return pi, false
	}
	ppid, utime, stime, start := parseStat(stContent)
	pi.PPID = ppid

	statusPath := fmt.Sprintf("/proc/%d/status", pid)
	status, err := os.ReadFile(statusPath)
	if err == nil {
		uid, rss, swap := parseStatus(status)
		pi.RSSKiB = rss
		pi.SwapKiB = swap
		pi.User = mapUID(uidToName, uid)
	} else {
		pi.User = "unknown"
	}

	cmdPath := fmt.Sprintf("/proc/%d/cmdline", pid)
	if b, err := os.ReadFile(cmdPath); err == nil {
		pi.Cmdline = parseCmdline(b)
	}

	cgPath := fmt.Sprintf("/proc/%d/cgroup", pid)
	if b, err := os.ReadFile(cgPath); err == nil {
		in, id := detectContainerFromCgroup(string(b))
		pi.InContainer = in
		if id != "" {
			pi.ContainerID = id
		}
	}

	pi.CPUPercent = calcCPUPercent(utime, stime, start, uptimeSec, float64(hz))

	return pi, true
}

func parseStat(b []byte) (ppid int, utime, stime, start int64) {
	// осторожно: второе поле (comm) в скобках и может содержать пробелы.
	line := string(b)
	rp := strings.LastIndex(line, ")")
	if rp == -1 {
		return
	}
	after := strings.TrimSpace(line[rp+1:])
	fields := strings.Fields(after)
	// поля после comm начинаются с state (1), ppid (2) — т.е. ppid — fields[1]
	if len(fields) < 22 {
		return
	}
	ppid, _ = strconv.Atoi(fields[1])
	utime, _ = strconv.ParseInt(fields[11], 10, 64) // 14-е, но fields сдвинуты: здесь 11
	stime, _ = strconv.ParseInt(fields[12], 10, 64) // 15-е
	start, _ = strconv.ParseInt(fields[19], 10, 64) // 22-е
	return
}

func parseStatus(b []byte) (uid uint32, rssKiB, swapKiB int64) {
	sc := bufio.NewScanner(bytes.NewReader(b))
	for sc.Scan() {
		line := sc.Text()
		if strings.HasPrefix(line, "Uid:") {
			fs := strings.Fields(line)
			if len(fs) >= 2 {
				if u64, err := strconv.ParseUint(fs[1], 10, 32); err == nil {
					uid = uint32(u64)
				}
			}
		} else if strings.HasPrefix(line, "VmRSS:") {
			fs := strings.Fields(line)
			if len(fs) >= 2 {
				rssKiB, _ = strconv.ParseInt(fs[1], 10, 64)
			}
		} else if strings.HasPrefix(line, "VmSwap:") {
			fs := strings.Fields(line)
			if len(fs) >= 2 {
				swapKiB, _ = strconv.ParseInt(fs[1], 10, 64)
			}
		}
	}
	return
}

func parseCmdline(b []byte) string {
	if len(b) == 0 {
		return ""
	}
	parts := bytes.Split(b, []byte{0})
	var out []string
	for _, p := range parts {
		if len(p) > 0 {
			out = append(out, string(p))
		}
	}
	return strings.Join(out, " ")
}

func detectContainerFromCgroup(cg string) (in bool, id string) {
	// Ищем шаблоны docker/<id>, docker-<id>.scope, kubepods..., containerd/io.containerd.runtime.v2.task/.../<id>
	lines := strings.Split(cg, "\n")
	for _, ln := range lines {
		if ln == "" {
			continue
		}
		parts := strings.SplitN(ln, ":", 3)
		if len(parts) != 3 {
			continue
		}
		path := parts[2]
		// common docker patterns
		if i := strings.Index(path, "/docker/"); i >= 0 {
			cand := path[i+len("/docker/"):]
			id = takeHexID(cand)
		} else if i := strings.Index(path, "docker-"); i >= 0 && strings.HasSuffix(path, ".scope") {
			cand := path[i+len("docker-"):]
			cand = strings.TrimSuffix(cand, ".scope")
			id = takeHexID(cand)
		} else if strings.Contains(path, "kubepods") && strings.Contains(path, "crio-") {
			// crio-<id>.scope
			i := strings.Index(path, "crio-")
			cand := path[i+5:]
			cand = strings.TrimSuffix(cand, ".scope")
			id = takeHexID(cand)
		} else if strings.Contains(path, "kubepods") && strings.Contains(path, "containerd://") {
			// not typical in cgroup path; often containerd id appears as .../<id>
		} else if strings.Contains(path, "containerd") {
			// try last segment
			segs := strings.Split(path, "/")
			if len(segs) > 0 {
				id = takeHexID(segs[len(segs)-1])
			}
		}
		if id != "" {
			return true, id
		}
	}
	return false, ""
}

func takeHexID(s string) string {
	// Возвращает длинный/короткий hex префикс
	hex := make([]rune, 0, len(s))
	for _, r := range s {
		if (r >= 'a' && r <= 'f') || (r >= '0' && r <= '9') {
			hex = append(hex, r)
		} else {
			break
		}
	}
	return string(hex)
}

func calcCPUPercent(utime, stime, start int64, uptimeSec float64, hz float64) float64 {
	totalTicks := float64(utime+stime)
	totalSec := totalTicks / hz
	elapsedSec := uptimeSec - (float64(start) / hz)
	if elapsedSec <= 0 {
		return 0
	}
	v := 100.0 * totalSec / elapsedSec
	if v < 0 {
		return 0
	}
	return v
}

func readUptime() (float64, error) {
	b, err := os.ReadFile("/proc/uptime")
	if err != nil {
		return 0, err
	}
	fs := strings.Fields(string(b))
	if len(fs) < 1 {
		return 0, errors.New("bad uptime")
	}
	return strconv.ParseFloat(fs[0], 64)
}

func clockTicks() (int64, error) {
	// sysconf via syscall? No direct; use unix.Sysconf if available; else fallback
	// On Go, we can use syscall.Sysinfo? Not providing HZ. Use env or fallback.
	return 100, nil
}

func loadPasswd() (map[uint32]string, error) {
	f, err := os.Open("/etc/passwd")
	if err != nil {
		return nil, err
	}
	defer f.Close()
	m := make(map[uint32]string)
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := sc.Text()
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		parts := strings.Split(line, ":")
		if len(parts) < 3 {
			continue
		}
		name := parts[0]
		uid64, err := strconv.ParseUint(parts[2], 10, 32)
		if err != nil {
			continue
		}
		m[uint32(uid64)] = name
	}
	return m, nil
}

func mapUID(m map[uint32]string, uid uint32) string {
	if name, ok := m[uid]; ok {
		return name
	}
	return strconv.FormatUint(uint64(uid), 10)
}

func dockerNameByID(id string) (string, error) {
	// GET /v1.41/containers/{id}/json
	sock := "/var/run/docker.sock"
	c := &http.Client{
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				return net.Dial("unix", sock)
			},
		},
		Timeout: 500 * time.Millisecond,
	}
	req, _ := http.NewRequest("GET", "http://unix/v1.41/containers/"+id+"/json", nil)
	resp, err := c.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		io.Copy(io.Discard, resp.Body)
		return "", fmt.Errorf("status %d", resp.StatusCode)
	}
	var v struct {
		Name string `json:"Name"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&v); err != nil {
		return "", err
	}
	return v.Name, nil
}

func buildPIDSet(expr string) map[int]bool {
	if strings.TrimSpace(expr) == "" {
		return nil
	}
	set := map[int]bool{}
	parts := strings.Split(expr, ",")
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		if strings.Contains(p, "-") {
			se := strings.SplitN(p, "-", 2)
			if len(se) == 2 {
				a, _ := strconv.Atoi(se[0])
				b, _ := strconv.Atoi(se[1])
				if a > b {
					a, b = b, a
				}
				for i := a; i <= b; i++ {
					set[i] = true
				}
			}
		} else {
			if v, err := strconv.Atoi(p); err == nil {
				set[v] = true
			}
		}
	}
	return set
}

func parseUserExpr(e string, uidToName map[uint32]string) (value string, isUID bool, err error) {
	e = strings.TrimSpace(e)
	if e == "" {
		return "", false, nil
	}
	if allDigits(e) {
		return e, true, nil
	}
	// Validate presence? optional
	return e, false, nil
}

func allDigits(s string) bool {
	for _, r := range s {
		if r < '0' || r > '9' {
			return false
		}
	}
	return s != ""
}

func filterFields(in []ProcInfo, opts *Options) []map[string]any {
	out := make([]map[string]any, 0, len(in))
	for _, p := range in {
		row := map[string]any{
			"pid":  p.PID,
			"ppid": p.PPID,
		}
		if opts.ShowCPU {
			row["cpu"] = fmt.Sprintf("%.2f", p.CPUPercent)
		}
		if opts.ShowMem {
			row["rss_kb"] = p.RSSKiB
		}
		if opts.ShowSwap {
			row["swap_kb"] = p.SwapKiB
		}
		if opts.ShowCmd {
			row["cmd"] = p.Cmdline
		}
		if opts.ShowUser {
			row["user"] = p.User
		}
		if opts.ShowContainer {
			row["in_container"] = p.InContainer
		}
		if opts.ShowContainerID {
			row["container_id"] = maybeTrunc(p.ContainerID, opts)
		}
		if opts.ShowContainerName {
			row["container_name"] = p.ContainerName
		}
		out = append(out, row)
	}
	return out
}

func maybeTrunc(s string, opts *Options) string {
	if opts.NoTrunc || len(s) <= 12 {
		return s
	}
	return s[:12]
}

func printTable(rows []map[string]any, opts *Options) {
	// Минимальный табличный вывод без сторонних зависимостей
	// Соберём заголовки в желаемом порядке:
	cols := []string{"pid", "ppid"}
	if opts.ShowCPU {
		cols = append(cols, "cpu")
	}
	if opts.ShowMem {
		cols = append(cols, "rss_kb")
	}
	if opts.ShowSwap {
		cols = append(cols, "swap_kb")
	}
	if opts.ShowUser {
		cols = append(cols, "user")
	}
	if opts.ShowContainer {
		cols = append(cols, "in_container")
	}
	if opts.ShowContainerID {
		cols = append(cols, "container_id")
	}
	if opts.ShowContainerName {
		cols = append(cols, "container_name")
	}
	if opts.ShowCmd {
		cols = append(cols, "cmd")
	}

	// Вывод заголовка
	for i, c := range cols {
		if i > 0 {
			fmt.Print("\t")
		}
		fmt.Print(strings.ToUpper(c))
	}
	fmt.Println()

	for _, r := range rows {
		for i, c := range cols {
			if i > 0 {
				fmt.Print("\t")
			}
			v, ok := r[c]
			if !ok {
				fmt.Print("")
				continue
			}
			fmt.Print(v)
		}
		fmt.Println()
	}
}
