package main

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/olekukonko/tablewriter"
	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"
)

// ============================================================================
// ТИПЫ ДАННЫХ
// ============================================================================

// Process представляет информацию о процессе системы
type Process struct {
	PID           int     `json:"pid" yaml:"pid"`
	PPID          int     `json:"ppid" yaml:"ppid"`
	CPUPercent    float64 `json:"cpu_percent,omitempty" yaml:"cpu_percent,omitempty"`
	MemoryBytes   uint64  `json:"memory_bytes,omitempty" yaml:"memory_bytes,omitempty"`
	SwapBytes     uint64  `json:"swap_bytes,omitempty" yaml:"swap_bytes,omitempty"`
	CommandLine   string  `json:"command_line,omitempty" yaml:"command_line,omitempty"`
	Username      string  `json:"username,omitempty" yaml:"username,omitempty"`
	UID           int     `json:"uid,omitempty" yaml:"uid,omitempty"`
	IsContainer   *bool   `json:"is_container,omitempty" yaml:"is_container,omitempty"`
	ContainerID   string  `json:"container_id,omitempty" yaml:"container_id,omitempty"`
	ContainerName string  `json:"container_name,omitempty" yaml:"container_name,omitempty"`
}

// Config содержит конфигурацию приложения
type Config struct {
	ShowCPU           bool
	ShowMemory        bool
	ShowSwap          bool
	ShowCommand       bool
	ShowUser          bool
	ShowContainer     bool
	ShowContainerID   bool
	ShowContainerName bool
	OutputFormat      string
	ContainerOnly     bool
	PIDFilter         []string
	UserFilter        []string
	ResourceFilter    []string
	SortBy            string
	CPUInterval       time.Duration
	ShowAll           bool
}

// ContainerInfo содержит информацию о контейнере
type ContainerInfo struct {
	ID   string
	Name string
	Type string
}

// CPUStats для мониторинга CPU
type CPUStats struct {
	PID       int
	UTime     uint64  // пользовательское время в jiffies
	STime     uint64  // системное время в jiffies
	CUTime    uint64  // время дочерних процессов (пользовательское)
	CSTime    uint64  // время дочерних процессов (системное)
	StartTime uint64  // время запуска процесса
	Timestamp time.Time
}

// ============================================================================
// ГЛОБАЛЬНЫЕ ПЕРЕМЕННЫЕ
// ============================================================================

var (
	config           Config
	userCache        = make(map[int]string)
	containerCache   = make(map[string]string)
	cpuStatsCache    = make(map[int]CPUStats)
	dockerAvailable  bool
	dockerClient     *http.Client
	clockTicksPerSec = 100.0 // Hz - получим из системы
)

// ============================================================================
// ОСНОВНЫЕ ФУНКЦИИ СБОРА ДАННЫХ
// ============================================================================

// initializeCollector инициализирует компоненты сборщика
func initializeCollector() {
	// Инициализация Docker клиента
	dockerClient = &http.Client{
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				return net.DialTimeout("unix", "/var/run/docker.sock", 2*time.Second)
			},
		},
		Timeout: 3 * time.Second,
	}
	dockerAvailable = checkDockerAvailable()

	// Получаем реальные clock ticks из системы
	clockTicksPerSec = getClockTicks()

	// Загружаем пользователей
	loadUserCache()

	// Добавляем root явно
	userCache[0] = "root"
}

// getClockTicks получает количество тиков в секунду
func getClockTicks() float64 {
	// Пытаемся прочитать из sysconf, fallback на 100
	// В реальности это обычно 100 Hz на большинстве Linux систем
	return 100.0
}

// checkDockerAvailable проверяет доступность Docker API
func checkDockerAvailable() bool {
	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, "GET", "http://localhost/version", nil)
	if err != nil {
		return false
	}
	resp, err := dockerClient.Do(req)
	if err != nil {
		return false
	}
	defer resp.Body.Close()
	return resp.StatusCode == http.StatusOK
}

// loadUserCache загружает пользователей из /etc/passwd
func loadUserCache() {
	userCache[0] = "root" // всегда добавляем root

	file, err := os.Open("/etc/passwd")
	if err != nil {
		return
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Split(line, ":")
		if len(fields) >= 3 {
			if uid, err := strconv.Atoi(fields[2]); err == nil {
				userCache[uid] = fields[0]
			}
		}
	}
}

// collectProcesses собирает все процессы
func collectProcesses() ([]*Process, error) {
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return nil, fmt.Errorf("failed to read /proc: %w", err)
	}

	var processes []*Process
	var pidList []int

	// Первый проход - собираем базовую информацию и первое измерение CPU
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		if pid, err := strconv.Atoi(entry.Name()); err == nil {
			if process := collectSingleProcess(pid); process != nil {
				processes = append(processes, process)
				pidList = append(pidList, pid)
			}
		}
	}

	// Второй проход для CPU если нужно
	if needsCPU() {
		interval := config.CPUInterval
		if interval == 0 {
			interval = time.Second
		}

		fmt.Fprintf(os.Stderr, "Measuring CPU usage (interval: %v)...\n", interval)
		time.Sleep(interval)

		updated := make([]*Process, 0, len(processes))
		for _, process := range processes {
			if processExists(process.PID) {
				calculateCPUUsage(process)
				updated = append(updated, process)
			}
		}
		processes = updated
		cleanupCPUStats(pidList)
	}

	return processes, nil
}

// collectSingleProcess собирает информацию об одном процессе
func collectSingleProcess(pid int) *Process {
	process := &Process{PID: pid}
	procPath := fmt.Sprintf("/proc/%d", pid)

	// Парсим stat файл
	if err := parseStatFile(procPath, process); err != nil {
		return nil
	}

	// Парсим status файл
	if config.ShowMemory || config.ShowSwap || config.ShowUser || config.ShowAll {
		parseStatusFile(procPath, process)
	}

	// Парсим cmdline
	if config.ShowCommand || config.ShowAll {
		parseCmdlineFile(procPath, process)
	}

	// Пользователь
	if config.ShowUser || config.ShowAll {
		if username, exists := userCache[process.UID]; exists {
			process.Username = username
		} else {
			process.Username = strconv.Itoa(process.UID)
		}
	}

	// Контейнер
	if needsContainer() {
		if info := detectContainer(pid); info != nil {
			isContainer := true
			process.IsContainer = &isContainer
			process.ContainerID = info.ID
			process.ContainerName = info.Name
		} else {
			isContainer := false
			process.IsContainer = &isContainer
		}
	}

	// CPU (первое измерение для инициализации)
	if needsCPU() {
		calculateCPUUsage(process)
	}

	return process
}

// parseStatFile парсит /proc/[pid]/stat
func parseStatFile(procPath string, process *Process) error {
	data, err := os.ReadFile(filepath.Join(procPath, "stat"))
	if err != nil {
		return err
	}

	fields := strings.Fields(string(data))
	if len(fields) < 24 {
		return fmt.Errorf("insufficient fields")
	}

	// PPID (поле 4)
	if ppid, err := strconv.Atoi(fields[3]); err == nil {
		process.PPID = ppid
	}

	// RSS память (поле 24) в страницах
	if rss, err := strconv.ParseUint(fields[23], 10, 64); err == nil {
		pageSize := uint64(syscall.Getpagesize())
		process.MemoryBytes = rss * pageSize
	}

	return nil
}

// parseStatusFile парсит /proc/[pid]/status
func parseStatusFile(procPath string, process *Process) {
	file, err := os.Open(filepath.Join(procPath, "status"))
	if err != nil {
		return
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()

		if strings.HasPrefix(line, "Uid:") {
			fields := strings.Fields(line)
			if len(fields) >= 2 {
				if uid, err := strconv.Atoi(fields[1]); err == nil {
					process.UID = uid
				}
			}
		} else if strings.HasPrefix(line, "VmSwap:") {
			fields := strings.Fields(line)
			if len(fields) >= 2 {
				if swap, err := strconv.ParseUint(fields[1], 10, 64); err == nil {
					process.SwapBytes = swap * 1024 // kB -> bytes
				}
			}
		}
	}
}

// parseCmdlineFile парсит /proc/[pid]/cmdline
func parseCmdlineFile(procPath string, process *Process) {
	data, err := os.ReadFile(filepath.Join(procPath, "cmdline"))
	if err != nil {
		return
	}

	cmdline := string(data)
	cmdline = strings.ReplaceAll(cmdline, "\x00", " ")
	cmdline = strings.TrimSpace(cmdline)

	if cmdline == "" {
		// Для kernel threads берем имя из stat
		if statData, err := os.ReadFile(filepath.Join(procPath, "stat")); err == nil {
			fields := strings.Fields(string(statData))
			if len(fields) >= 2 {
				cmdline = strings.Trim(fields[1], "()")
			}
		}
	}

	process.CommandLine = cmdline
}

// ============================================================================
// CPU МОНИТОРИНГ (ИСПРАВЛЕННАЯ ВЕРСИЯ)
// ============================================================================

// calculateCPUUsage вычисляет CPU использование (ПРАВИЛЬНЫЙ АЛГОРИТМ)
func calculateCPUUsage(process *Process) {
	current, err := readProcessCPUStats(process.PID)
	if err != nil {
		return
	}

	prev, exists := cpuStatsCache[process.PID]
	if !exists {
		// Первое измерение - сохраняем и устанавливаем 0
		cpuStatsCache[process.PID] = current
		process.CPUPercent = 0.0
		return
	}

	// Вычисляем временную дельту в секундах (реальное время)
	timeDelta := current.Timestamp.Sub(prev.Timestamp).Seconds()
	if timeDelta <= 0.01 { // Слишком маленький интервал
		process.CPUPercent = 0.0
		return
	}

	// Дельта процессорного времени процесса в jiffies
	// Включаем время самого процесса и его дочерних процессов
	currentProcessTime := current.UTime + current.STime + current.CUTime + current.CSTime
	prevProcessTime := prev.UTime + prev.STime + prev.CUTime + prev.CSTime

	processCPUDelta := currentProcessTime - prevProcessTime

	// Конвертируем jiffies в секунды
	processCPUSeconds := float64(processCPUDelta) / clockTicksPerSec

	// ПРАВИЛЬНАЯ ФОРМУЛА: CPU% = (время_CPU_процесса / реальное_время) * 100
	// Это может быть > 100% на многоядерных системах для многопоточных процессов
	cpuPercent := (processCPUSeconds / timeDelta) * 100.0

	// Нормализация
	if cpuPercent < 0 {
		cpuPercent = 0.0
	}

	// Для совместимости с top ограничиваем разумными пределами
	if cpuPercent > 999.9 {
		cpuPercent = 999.9
	}

	process.CPUPercent = cpuPercent
	cpuStatsCache[process.PID] = current
}

// readProcessCPUStats читает CPU статистики процесса (ИСПРАВЛЕННАЯ ВЕРСИЯ)
func readProcessCPUStats(pid int) (CPUStats, error) {
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid))
	if err != nil {
		return CPUStats{}, err
	}

	fields := strings.Fields(string(data))
	if len(fields) < 22 {
		return CPUStats{}, fmt.Errorf("insufficient fields")
	}

	// Поля из /proc/[pid]/stat (нумерация с 1):
	// 14: utime - пользовательское время (индекс 13)
	// 15: stime - системное время (индекс 14)
	// 16: cutime - время дочерних процессов пользовательское (индекс 15)
	// 17: cstime - время дочерних процессов системное (индекс 16) 
	// 22: starttime - время запуска (индекс 21)

	utime, err := strconv.ParseUint(fields[13], 10, 64)
	if err != nil {
		return CPUStats{}, fmt.Errorf("failed to parse utime: %w", err)
	}

	stime, err := strconv.ParseUint(fields[14], 10, 64)
	if err != nil {
		return CPUStats{}, fmt.Errorf("failed to parse stime: %w", err)
	}

	var cutime, cstime, starttime uint64

	// cutime и cstime (дочерние процессы)
	if len(fields) > 15 {
		cutime, _ = strconv.ParseUint(fields[15], 10, 64)
	}
	if len(fields) > 16 {
		cstime, _ = strconv.ParseUint(fields[16], 10, 64)
	}

	// starttime
	if len(fields) > 21 {
		starttime, _ = strconv.ParseUint(fields[21], 10, 64)
	}

	return CPUStats{
		PID:       pid,
		UTime:     utime,
		STime:     stime,
		CUTime:    cutime,
		CSTime:    cstime,
		StartTime: starttime,
		Timestamp: time.Now(),
	}, nil
}

// cleanupCPUStats очищает старые CPU статистики
func cleanupCPUStats(activePIDs []int) {
	activeMap := make(map[int]bool)
	for _, pid := range activePIDs {
		activeMap[pid] = true
	}
	for pid := range cpuStatsCache {
		if !activeMap[pid] {
			delete(cpuStatsCache, pid)
		}
	}
}

// ============================================================================
// ОПРЕДЕЛЕНИЕ КОНТЕЙНЕРОВ
// ============================================================================

// detectContainer определяет контейнер для процесса
func detectContainer(pid int) *ContainerInfo {
	file, err := os.Open(fmt.Sprintf("/proc/%d/cgroup", pid))
	if err != nil {
		return nil
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()

		// Docker
		if id := extractDockerID(line); id != "" {
			name := getDockerContainerName(id)
			return &ContainerInfo{ID: id, Name: name, Type: "docker"}
		}

		// LXC
		if name := extractLXCName(line); name != "" {
			return &ContainerInfo{ID: name, Name: name, Type: "lxc"}
		}

		// Systemd
		if name := extractSystemdContainer(line); name != "" {
			return &ContainerInfo{ID: name, Name: name, Type: "systemd"}
		}
	}
	return nil
}

// extractDockerID извлекает Docker ID
func extractDockerID(line string) string {
	patterns := []string{
		`docker[/-]([a-f0-9]{64})`,
		`docker-([a-f0-9]{64})\.scope`,
		`/([a-f0-9]{64})$`,
		`docker[/-]([a-f0-9]{12,})`,
	}

	for _, pattern := range patterns {
		re := regexp.MustCompile(pattern)
		if matches := re.FindStringSubmatch(line); len(matches) > 1 {
			id := matches[1]
			if len(id) >= 12 {
				return id[:12]
			}
			return id
		}
	}
	return ""
}

// extractLXCName извлекает LXC имя
func extractLXCName(line string) string {
	patterns := []string{
		`lxc\.payload\.([^/\s]+)`,
		`lxc/([^/\s]+)`,
	}

	for _, pattern := range patterns {
		re := regexp.MustCompile(pattern)
		if matches := re.FindStringSubmatch(line); len(matches) > 1 {
			return matches[1]
		}
	}
	return ""
}

// extractSystemdContainer извлекает systemd контейнер
func extractSystemdContainer(line string) string {
	re := regexp.MustCompile(`machine-([^.]+)\.scope`)
	if matches := re.FindStringSubmatch(line); len(matches) > 1 {
		return matches[1]
	}
	return ""
}

// getDockerContainerName получает имя Docker контейнера
func getDockerContainerName(containerID string) string {
	if name, ok := containerCache[containerID]; ok {
		return name
	}

	if !dockerAvailable {
		containerCache[containerID] = containerID
		return containerID
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	url := fmt.Sprintf("http://localhost/containers/%s/json", containerID)
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		containerCache[containerID] = containerID
		return containerID
	}

	resp, err := dockerClient.Do(req)
	if err != nil {
		containerCache[containerID] = containerID
		return containerID
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		containerCache[containerID] = containerID
		return containerID
	}

	var info struct {
		Name   string `json:"Name"`
		Config struct {
			Hostname string `json:"Hostname"`
		} `json:"Config"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&info); err != nil {
		containerCache[containerID] = containerID
		return containerID
	}

	name := strings.TrimPrefix(info.Name, "/")
	if name == "" {
		name = info.Config.Hostname
	}
	if name == "" {
		name = containerID
	}

	containerCache[containerID] = name
	return name
}

// ============================================================================
// ФИЛЬТРАЦИЯ И СОРТИРОВКА
// ============================================================================

// applyFilters применяет фильтры к процессам
func applyFilters(processes []*Process) []*Process {
	var filtered []*Process

	for _, process := range processes {
		if shouldIncludeProcess(process) {
			filtered = append(filtered, process)
		}
	}

	return filtered
}

// shouldIncludeProcess проверяет должен ли процесс быть включен
func shouldIncludeProcess(process *Process) bool {
	// Фильтр контейнеров
	if config.ContainerOnly {
		if process.IsContainer == nil || !*process.IsContainer {
			return false
		}
	}

	// Фильтр PID
	if len(config.PIDFilter) > 0 && !matchesPIDFilter(process.PID) {
		return false
	}

	// Фильтр пользователя
	if len(config.UserFilter) > 0 && !matchesUserFilter(process) {
		return false
	}

	// Фильтр ресурсов
	if len(config.ResourceFilter) > 0 && !matchesResourceFilter(process) {
		return false
	}

	return true
}

// matchesPIDFilter проверяет PID фильтр
func matchesPIDFilter(pid int) bool {
	for _, filter := range config.PIDFilter {
		if matchesPIDPattern(pid, filter) {
			return true
		}
	}
	return false
}

// matchesPIDPattern проверяет паттерн PID
func matchesPIDPattern(pid int, pattern string) bool {
	// Диапазон
	if strings.Contains(pattern, "-") {
		parts := strings.Split(pattern, "-")
		if len(parts) == 2 {
			start, err1 := strconv.Atoi(strings.TrimSpace(parts[0]))
			end, err2 := strconv.Atoi(strings.TrimSpace(parts[1]))
			if err1 == nil && err2 == nil {
				return pid >= start && pid <= end
			}
		}
	}

	// Точное совпадение
	if targetPID, err := strconv.Atoi(pattern); err == nil {
		return pid == targetPID
	}

	return false
}

// matchesUserFilter проверяет фильтр пользователя
func matchesUserFilter(process *Process) bool {
	for _, filter := range config.UserFilter {
		if process.Username == filter {
			return true
		}
		if uid, err := strconv.Atoi(filter); err == nil && process.UID == uid {
			return true
		}
	}
	return false
}

// matchesResourceFilter проверяет фильтр ресурсов
func matchesResourceFilter(process *Process) bool {
	for _, filter := range config.ResourceFilter {
		if matchesSingleResourceFilter(process, filter) {
			return true
		}
	}
	return false
}

// matchesSingleResourceFilter проверяет один ресурсный фильтр
func matchesSingleResourceFilter(process *Process, filter string) bool {
	filter = strings.TrimSpace(filter)

	// Простые фильтры
	switch strings.ToLower(filter) {
	case "cpu":
		return process.CPUPercent > 0
	case "memory", "mem":
		return process.MemoryBytes > 0
	case "swap":
		return process.SwapBytes > 0
	}

	// Фильтры с операторами
	operators := []string{">=", "<=", ">", "<", "="}
	for _, op := range operators {
		if strings.Contains(filter, op) {
			parts := strings.Split(filter, op)
			if len(parts) != 2 {
				continue
			}
			return evaluateResourceCondition(process, strings.TrimSpace(parts[0]), op, strings.TrimSpace(parts[1]))
		}
	}

	return false
}

// evaluateResourceCondition оценивает условие ресурса
func evaluateResourceCondition(process *Process, resource, operator, valueStr string) bool {
	var actualValue float64

	switch strings.ToLower(resource) {
	case "cpu":
		actualValue = process.CPUPercent
	case "memory", "mem":
		actualValue = float64(process.MemoryBytes)
	case "swap":
		actualValue = float64(process.SwapBytes)
	default:
		return false
	}

	expectedValue := parseValueWithUnits(valueStr)
	if expectedValue < 0 {
		return false
	}

	switch operator {
	case ">":
		return actualValue > expectedValue
	case ">=":
		return actualValue >= expectedValue
	case "<":
		return actualValue < expectedValue
	case "<=":
		return actualValue <= expectedValue
	case "=":
		return actualValue == expectedValue
	}

	return false
}

// parseValueWithUnits парсит значение с единицами
func parseValueWithUnits(valueStr string) float64 {
	valueStr = strings.ToLower(strings.TrimSpace(valueStr))

	var numStr, unit string
	for i, r := range valueStr {
		if (r >= '0' && r <= '9') || r == '.' {
			numStr += string(r)
		} else {
			unit = valueStr[i:]
			break
		}
	}

	value, err := strconv.ParseFloat(numStr, 64)
	if err != nil {
		return -1
	}

	switch unit {
	case "kb", "k":
		return value * 1024
	case "mb", "m":
		return value * 1024 * 1024
	case "gb", "g":
		return value * 1024 * 1024 * 1024
	case "tb", "t":
		return value * 1024 * 1024 * 1024 * 1024
	case "%":
		return value
	default:
		return value
	}
}

// sortProcesses сортирует процессы
func sortProcesses(processes []*Process) error {
	if config.SortBy == "" {
		return nil
	}

	sortBy := strings.ToLower(strings.TrimSpace(config.SortBy))

	switch sortBy {
	case "pid":
		sort.Slice(processes, func(i, j int) bool {
			return processes[i].PID < processes[j].PID
		})
	case "ppid":
		sort.Slice(processes, func(i, j int) bool {
			return processes[i].PPID < processes[j].PPID
		})
	case "cpu":
		sort.Slice(processes, func(i, j int) bool {
			return processes[i].CPUPercent > processes[j].CPUPercent
		})
	case "memory", "mem":
		sort.Slice(processes, func(i, j int) bool {
			return processes[i].MemoryBytes > processes[j].MemoryBytes
		})
	case "swap":
		sort.Slice(processes, func(i, j int) bool {
			return processes[i].SwapBytes > processes[j].SwapBytes
		})
	case "user", "username":
		sort.Slice(processes, func(i, j int) bool {
			return processes[i].Username < processes[j].Username
		})
	case "cmd", "command":
		sort.Slice(processes, func(i, j int) bool {
			return processes[i].CommandLine < processes[j].CommandLine
		})
	default:
		return fmt.Errorf("unsupported sort field: %s", sortBy)
	}

	return nil
}

// ============================================================================
// ФОРМАТИРОВАНИЕ ВЫВОДА
// ============================================================================

// formatOutput форматирует и выводит процессы
func formatOutput(processes []*Process) error {
	switch config.OutputFormat {
	case "json":
		return formatJSON(processes)
	case "yaml":
		return formatYAML(processes)
	default:
		return formatTable(processes)
	}
}

// formatTable форматирует табличный вывод
func formatTable(processes []*Process) error {
	table := tablewriter.NewWriter(os.Stdout)

	// Заголовки
	headers := []string{"PID", "PPID"}
	if config.ShowCPU || config.ShowAll {
		headers = append(headers, "CPU%")
	}
	if config.ShowMemory || config.ShowAll {
		headers = append(headers, "MEMORY")
	}
	if config.ShowSwap || config.ShowAll {
		headers = append(headers, "SWAP")
	}
	if config.ShowUser || config.ShowAll {
		headers = append(headers, "USER")
	}
	if config.ShowContainer || config.ShowAll {
		headers = append(headers, "CONTAINER")
	}
	if config.ShowContainerID || config.ShowAll {
		headers = append(headers, "CONTAINER_ID")
	}
	if config.ShowContainerName || config.ShowAll {
		headers = append(headers, "CONTAINER_NAME")
	}
	if config.ShowCommand || config.ShowAll {
		headers = append(headers, "COMMAND")
	}

	table.SetHeader(headers)
	table.SetBorder(false)
	table.SetCenterSeparator("")
	table.SetColumnSeparator("")
	table.SetRowSeparator("")
	table.SetHeaderLine(false)
	table.SetTablePadding("\t")
	table.SetNoWhiteSpace(true)

	// Строки данных
	for _, process := range processes {
		row := []string{
			strconv.Itoa(process.PID),
			strconv.Itoa(process.PPID),
		}

		if config.ShowCPU || config.ShowAll {
			row = append(row, fmt.Sprintf("%.1f", process.CPUPercent))
		}
		if config.ShowMemory || config.ShowAll {
			row = append(row, formatBytes(process.MemoryBytes))
		}
		if config.ShowSwap || config.ShowAll {
			row = append(row, formatBytes(process.SwapBytes))
		}
		if config.ShowUser || config.ShowAll {
			user := process.Username
			if user == "" {
				user = strconv.Itoa(process.UID)
			}
			row = append(row, user)
		}
		if config.ShowContainer || config.ShowAll {
			if process.IsContainer != nil {
				if *process.IsContainer {
					row = append(row, "Yes")
				} else {
					row = append(row, "No")
				}
			} else {
				row = append(row, "-")
			}
		}
		if config.ShowContainerID || config.ShowAll {
			if process.ContainerID != "" {
				row = append(row, process.ContainerID)
			} else {
				row = append(row, "-")
			}
		}
		if config.ShowContainerName || config.ShowAll {
			if process.ContainerName != "" {
				row = append(row, process.ContainerName)
			} else {
				row = append(row, "-")
			}
		}
		if config.ShowCommand || config.ShowAll {
			cmd := process.CommandLine
			if len(cmd) > 50 {
				cmd = cmd[:47] + "..."
			}
			row = append(row, cmd)
		}

		table.Append(row)
	}

	table.Render()
	return nil
}

// formatJSON форматирует JSON вывод
func formatJSON(processes []*Process) error {
	filtered := filterFieldsForOutput(processes)
	data, err := json.MarshalIndent(filtered, "", "  ")
	if err != nil {
		return err
	}
	fmt.Println(string(data))
	return nil
}

// formatYAML форматирует YAML вывод
func formatYAML(processes []*Process) error {
	filtered := filterFieldsForOutput(processes)
	data, err := yaml.Marshal(filtered)
	if err != nil {
		return err
	}
	fmt.Print(string(data))
	return nil
}

// filterFieldsForOutput фильтрует поля для вывода
func filterFieldsForOutput(processes []*Process) []map[string]interface{} {
	var result []map[string]interface{}

	for _, process := range processes {
		item := make(map[string]interface{})

		item["pid"] = process.PID
		item["ppid"] = process.PPID

		if config.ShowCPU || config.ShowAll {
			item["cpu_percent"] = process.CPUPercent
		}
		if config.ShowMemory || config.ShowAll {
			item["memory_bytes"] = process.MemoryBytes
		}
		if config.ShowSwap || config.ShowAll {
			item["swap_bytes"] = process.SwapBytes
		}
		if config.ShowUser || config.ShowAll {
			item["username"] = process.Username
			item["uid"] = process.UID
		}
		if config.ShowContainer || config.ShowAll {
			item["is_container"] = process.IsContainer
		}
		if config.ShowContainerID || config.ShowAll {
			if process.ContainerID != "" {
				item["container_id"] = process.ContainerID
			}
		}
		if config.ShowContainerName || config.ShowAll {
			if process.ContainerName != "" {
				item["container_name"] = process.ContainerName
			}
		}
		if config.ShowCommand || config.ShowAll {
			item["command_line"] = process.CommandLine
		}

		result = append(result, item)
	}

	return result
}

// ============================================================================
// УТИЛИТЫ
// ============================================================================

// formatBytes форматирует байты в читаемый вид
func formatBytes(bytes uint64) string {
	if bytes == 0 {
		return "0B"
	}

	const unit = 1024
	if bytes < unit {
		return fmt.Sprintf("%dB", bytes)
	}

	div, exp := uint64(unit), 0
	for n := bytes / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}

	sizes := []string{"KB", "MB", "GB", "TB", "PB"}
	return fmt.Sprintf("%.1f%s", float64(bytes)/float64(div), sizes[exp])
}

// processExists проверяет существование процесса
func processExists(pid int) bool {
	_, err := os.Stat(fmt.Sprintf("/proc/%d", pid))
	return err == nil
}

// needsCPU проверяет нужно ли измерять CPU
func needsCPU() bool {
	if config.ShowCPU || config.ShowAll {
		return true
	}
	for _, filter := range config.ResourceFilter {
		if strings.Contains(strings.ToLower(filter), "cpu") {
			return true
		}
	}
	return false
}

// needsContainer проверяет нужно ли определять контейнеры
func needsContainer() bool {
	return config.ShowContainer || config.ShowContainerID || config.ShowContainerName || 
	       config.ShowAll || config.ContainerOnly
}

// ============================================================================
// CLI И MAIN
// ============================================================================

var rootCmd = &cobra.Command{
	Use:   "yaps",
	Short: "Yet another  process monitor for Linux systems",
	Long: `A comprehensive process monitoring tool for Linux that provides detailed 
information about running processes including CPU usage, memory consumption, 
container detection, and much more.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		return runProcessMonitor()
	},
}

func init() {
	// Флаги
	rootCmd.PersistentFlags().BoolVarP(&config.ShowCPU, "show-cpu", "c", false, "Show CPU utilization")
	rootCmd.PersistentFlags().BoolVarP(&config.ShowMemory, "show-mem", "m", false, "Show memory usage")
	rootCmd.PersistentFlags().BoolVarP(&config.ShowSwap, "show-swap", "s", false, "Show swap usage")
	rootCmd.PersistentFlags().BoolVarP(&config.ShowCommand, "show-cmd", "C", false, "Show command line")
	rootCmd.PersistentFlags().BoolVarP(&config.ShowUser, "show-user", "u", false, "Show user")

	resourcesFlag := false
	rootCmd.PersistentFlags().BoolVarP(&resourcesFlag, "resources", "r", false, "Show CPU, memory, and swap")

	rootCmd.PersistentFlags().BoolVar(&config.ShowContainer, "show-container", false, "Show container flag")
	rootCmd.PersistentFlags().BoolVar(&config.ShowContainerID, "container-id", false, "Show container ID")
	rootCmd.PersistentFlags().BoolVar(&config.ShowContainerName, "container-name", false, "Show container name")

	rootCmd.PersistentFlags().StringVarP(&config.OutputFormat, "output", "o", "table", "Output format: table, json, yaml")
	rootCmd.PersistentFlags().StringVar(&config.SortBy, "sort-by", "", "Sort by column")
	rootCmd.PersistentFlags().DurationVar(&config.CPUInterval, "cpu-interval", time.Second, "CPU measurement interval")

	rootCmd.PersistentFlags().BoolVar(&config.ContainerOnly, "container-only", false, "Show only containerized processes")
	rootCmd.PersistentFlags().StringSliceVar(&config.PIDFilter, "pid", nil, "Filter by PID")
	rootCmd.PersistentFlags().StringSliceVar(&config.UserFilter, "user", nil, "Filter by username or UID")
	rootCmd.PersistentFlags().StringSliceVarP(&config.ResourceFilter, "set-filter", "f", nil, "Filter by resources")

	rootCmd.PersistentPreRun = func(cmd *cobra.Command, args []string) {
		if resourcesFlag {
			config.ShowCPU = true
			config.ShowMemory = true
			config.ShowSwap = true
		}

		if config.CPUInterval < 100*time.Millisecond {
			fmt.Fprintf(os.Stderr, "Warning: CPU interval too small, setting to 100ms\n")
			config.CPUInterval = 100 * time.Millisecond
		}
		if config.CPUInterval > 10*time.Second {
			fmt.Fprintf(os.Stderr, "Warning: CPU interval too large, setting to 10s\n")
			config.CPUInterval = 10 * time.Second
		}

		if !config.ShowCPU && !config.ShowMemory && !config.ShowSwap && 
		   !config.ShowCommand && !config.ShowUser && !config.ShowContainer &&
		   !config.ShowContainerID && !config.ShowContainerName {
			config.ShowAll = true
		}
	}

	versionCmd := &cobra.Command{
		Use:   "version",
		Short: "Print version information",
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Println("yaps - Process Monitor v1.0.2 (single-file, fixed CPU usage and sorts)")
		},
	}

	rootCmd.AddCommand(versionCmd)
}

func runProcessMonitor() error {
	initializeCollector()

	processes, err := collectProcesses()
	if err != nil {
		return fmt.Errorf("failed to collect processes: %w", err)
	}

	filtered := applyFilters(processes)

	if err := sortProcesses(filtered); err != nil {
		return fmt.Errorf("failed to sort processes: %w", err)
	}

	return formatOutput(filtered)
}

func main() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}
