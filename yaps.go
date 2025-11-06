package main

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/tklauser/go-sysconf"
	"github.com/olekukonko/tablewriter"
	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"
)

// ============================================================================
// ТИПЫ ДАННЫХ
// ============================================================================

// Process представляет информацию о процессе системы
type Process struct {
	PID              int     `json:"pid" yaml:"pid"`
	PPID             int     `json:"ppid" yaml:"ppid"`
	CPUPercent       float64 `json:"cpu_percent,omitempty" yaml:"cpu_percent,omitempty"`
	MemoryBytes      uint64  `json:"memory_bytes,omitempty" yaml:"memory_bytes,omitempty"`
	SwapBytes        uint64  `json:"swap_bytes,omitempty" yaml:"swap_bytes,omitempty"`
	CommandLine      string  `json:"command_line,omitempty" yaml:"command_line,omitempty"`
	Username         string  `json:"username,omitempty" yaml:"username,omitempty"`
	UID              int     `json:"uid,omitempty" yaml:"uid,omitempty"`
	IsContainer      *bool   `json:"is_container,omitempty" yaml:"is_container,omitempty"`
	ContainerID      string  `json:"container_id,omitempty" yaml:"container_id,omitempty"`
	ContainerName    string  `json:"container_name,omitempty" yaml:"container_name,omitempty"`
	K8sNamespace     string  `json:"k8s_namespace,omitempty" yaml:"k8s_namespace,omitempty"`
	K8sPodName       string  `json:"k8s_pod_name,omitempty" yaml:"k8s_pod_name,omitempty"`
	K8sPodUID        string  `json:"k8s_pod_uid,omitempty" yaml:"k8s_pod_uid,omitempty"`
	K8sQoSClass      string  `json:"k8s_qos_class,omitempty" yaml:"k8s_qos_class,omitempty"`
	ContainerType    string  `json:"container_type,omitempty" yaml:"container_type,omitempty"`
}

// Config содержит конфигурацию приложения
type Config struct {
	ShowCPU          bool
	ShowMemory       bool
	ShowSwap         bool
	ShowCommand      bool
	ShowUser         bool
	ShowContainer    bool
	ShowContainerID  bool
	ShowContainerName bool
	OutputFormat     string
	ContainerOnly    bool
	PIDFilter        []string
	UserFilter       []string
	ResourceFilter   []string
	SortBy           string
	CPUInterval      time.Duration
	ShowAll          bool
	ShowKubernetes   bool
	K8sOnly          bool
	K8sNamespace     string
	K8sQoS           string
}

// ContainerInfoExtended расширенная информация о контейнере с K8s поддержкой
type ContainerInfoExtended struct {
	ID            string
	Name          string
	Type          string
	PodName       string
	PodNamespace  string
	PodUID        string
	ContainerName string
	QoSClass      string
	IsKubernetes  bool
	IsSandbox     bool
}

// ContainerInfo содержит информацию о контейнере (для совместимости)
type ContainerInfo struct {
	ID   string
	Name string
	Type string
}

// CPUStats для мониторинга CPU
type CPUStats struct {
	PID       int
	UTime     uint64
	STime     uint64
	CUTime    uint64
	CSTime    uint64
	StartTime uint64
	Timestamp time.Time
}

// K8sPodMetadata содержит метаданные пода из kubelet
type K8sPodMetadata struct {
	Name      string
	Namespace string
	UID       string
}

// CrictlContainerMetadata метаданные контейнера из crictl
type CrictlContainerMetadata struct {
	Name    string `json:"name"`
	Attempt uint32 `json:"attempt"`
}

// CrictlImageRef структура для image информации
type CrictlImageRef struct {
	Image       string `json:"image"`
	Annotations map[string]string `json:"annotations"`
}

// CrictlContainer структура для парсинга crictl ps
type CrictlContainer struct {
	ID           string                     `json:"id"`
	PodSandboxID string                     `json:"podSandboxId"`
	Metadata     CrictlContainerMetadata    `json:"metadata"`
	Image        CrictlImageRef             `json:"image"`
	ImageRef     string                     `json:"imageRef"`
	State        string                     `json:"state"`
	CreatedAt    string                     `json:"createdAt"`
	Labels       map[string]string          `json:"labels"`
	Annotations  map[string]string          `json:"annotations"`
}

// CrictlPodMetadata структура метаданных пода
type CrictlPodMetadata struct {
	Name      string `json:"name"`
	Namespace string `json:"namespace"`
	Attempt   uint32 `json:"attempt"`
	UID       string `json:"uid"`
}

// CrictlPod структура для парсинга crictl pods
type CrictlPod struct {
	ID        string               `json:"id"`
	Metadata  CrictlPodMetadata    `json:"metadata"`
	State     string               `json:"state"`
	CreatedAt string               `json:"createdAt"`
	Labels    map[string]string    `json:"labels"`
}

// ============================================================================
// ГЛОБАЛЬНЫЕ ПЕРЕМЕННЫЕ
// ============================================================================

var (
	config                Config
	userCache             = make(map[int]string)
	containerCache        = make(map[string]string)
	k8sMetadataCache      = make(map[string]*ContainerInfoExtended)
	cpuStatsCache         = make(map[int]CPUStats)
	dockerAvailable       bool
	dockerClient          *http.Client
	clockTicksPerSec      = 100.0
	crictlConfigPath      string
	containerNameByIDCache = make(map[string]string) // Container ID -> Name (from crictl)
	containerLabelsByIDCache = make(map[string]map[string]string) // Container ID -> Labels
	podMetadataByIDCache  = make(map[string]*CrictlPod) // Pod ID -> metadata (from crictl)
)

// ============================================================================
// CRICTL INTEGRATION
// ============================================================================

// initializeCrictlConfig инициализирует путь к конфигу crictl
func initializeCrictlConfig() {
	// Проверяем переменную окружения
	if path := os.Getenv("CRI_CONFIG_FILE"); path != "" {
		crictlConfigPath = path
		return
	}

	// Пути по умолчанию для RKE2 и стандартного k8s
	defaultPaths := []string{
		"/var/lib/rancher/rke2/agent/etc/crictl.yaml",
		"/etc/crictl.yaml",
		"/etc/cri-tools/crictl.yaml",
	}

	for _, path := range defaultPaths {
		if _, err := os.Stat(path); err == nil {
			crictlConfigPath = path
			return
		}
	}

	// Если ничего не найдено, используем стандартный путь RKE2
	crictlConfigPath = "/var/lib/rancher/rke2/agent/etc/crictl.yaml"
}

// loadContainerNamesViaCrictl загружает имена контейнеров через crictl ps
func loadContainerNamesViaCrictl() error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, "crictl", "ps", "-a", "--output=json")
	if crictlConfigPath != "" {
		cmd.Env = append(os.Environ(), fmt.Sprintf("CRI_CONFIG_FILE=%s", crictlConfigPath))
	}

	output, err := cmd.Output()
	if err != nil {
		if os.Getenv("DEBUG") != "" {
			fmt.Fprintf(os.Stderr, "Warning: Failed to run crictl ps: %v\n", err)
		}
		return err
	}

	var result struct {
		Containers []CrictlContainer `json:"containers"`
	}

	if err := json.Unmarshal(output, &result); err != nil {
		if os.Getenv("DEBUG") != "" {
			fmt.Fprintf(os.Stderr, "Warning: Failed to parse crictl ps output: %v\n", err)
		}
		return err
	}

	for _, container := range result.Containers {
		// Нормализуем container ID (берём первые 12 символов)
		shortID := container.ID
		if len(shortID) > 12 {
			shortID = shortID[:12]
		}
		
		// Сохраняем имя контейнера из metadata
		containerName := container.Metadata.Name
		containerNameByIDCache[shortID] = containerName
		
		// Сохраняем labels для последующего парсинга K8s информации
		if container.Labels != nil {
			containerLabelsByIDCache[shortID] = container.Labels
		}
		
		if os.Getenv("DEBUG") != "" {
			fmt.Fprintf(os.Stderr, "Debug: Loaded container %s -> name=%s\n", shortID, containerName)
		}
	}

	return nil
}

// loadPodMetadataViaCrictl загружает метаданные подов через crictl pods
func loadPodMetadataViaCrictl() error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, "crictl", "pods", "--output=json")
	if crictlConfigPath != "" {
		cmd.Env = append(os.Environ(), fmt.Sprintf("CRI_CONFIG_FILE=%s", crictlConfigPath))
	}

	output, err := cmd.Output()
	if err != nil {
		if os.Getenv("DEBUG") != "" {
			fmt.Fprintf(os.Stderr, "Warning: Failed to run crictl pods: %v\n", err)
		}
		return err
	}

	var result struct {
		Pods []CrictlPod `json:"pods"`
	}

	if err := json.Unmarshal(output, &result); err != nil {
		if os.Getenv("DEBUG") != "" {
			fmt.Fprintf(os.Stderr, "Warning: Failed to parse crictl pods output: %v\n", err)
		}
		return err
	}

	for i := range result.Pods {
		pod := &result.Pods[i]
		// Нормализуем pod ID (берём первые 12 символов)
		shortID := pod.ID
		if len(shortID) > 12 {
			shortID = shortID[:12]
		}
		podMetadataByIDCache[shortID] = pod
		if os.Getenv("DEBUG") != "" {
			fmt.Fprintf(os.Stderr, "Debug: Loaded pod %s -> %s/%s\n", shortID, pod.Metadata.Namespace, pod.Metadata.Name)
		}
	}

	return nil
}

// getContainerNameViaCrictl получает имя контейнера из кэша crictl
func getContainerNameViaCrictl(containerID string) string {
	if name, ok := containerNameByIDCache[containerID]; ok {
		return name
	}
	return containerID
}

// getContainerK8sLabels получает K8s labels контейнера из кэша crictl
func getContainerK8sLabels(containerID string) map[string]string {
	if labels, ok := containerLabelsByIDCache[containerID]; ok {
		return labels
	}
	return nil
}

// getPodMetadataViaCrictl получает метаданные пода из кэша crictl
func getPodMetadataViaCrictl(podUID string) *CrictlPod {
	// Пытаемся прямой поиск по UID
	if pod, ok := podMetadataByIDCache[podUID]; ok {
		return pod
	}

	// Пытаемся нормализовать UID и поискать
	normalizedUID := normalizePodUID(podUID)
	if normalizedUID != podUID {
		if len(normalizedUID) > 12 {
			normalizedUID = normalizedUID[:12]
		}
		if pod, ok := podMetadataByIDCache[normalizedUID]; ok {
			return pod
		}
	}

	// Пытаемся поиск по обратному преобразованию (_)
	cgroupUID := strings.ReplaceAll(podUID, "-", "_")
	for _, pod := range podMetadataByIDCache {
		if strings.HasPrefix(pod.Metadata.UID, strings.ReplaceAll(cgroupUID[:8], "-", "_")) {
			return pod
		}
		if strings.HasPrefix(pod.Metadata.UID, podUID[:8]) {
			return pod
		}
	}

	return nil
}

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

	// Инициализируем crictl конфиг
	initializeCrictlConfig()

	// Загружаем данные через crictl (если доступен)
	if err := loadContainerNamesViaCrictl(); err != nil {
		if os.Getenv("DEBUG") != "" {
			fmt.Fprintf(os.Stderr, "Debug: crictl ps not available or failed\n")
		}
	}

	if err := loadPodMetadataViaCrictl(); err != nil {
		if os.Getenv("DEBUG") != "" {
			fmt.Fprintf(os.Stderr, "Debug: crictl pods not available or failed\n")
		}
	}
}

func getClockTicks() float64 {
	clkTck, err := sysconf.Sysconf(sysconf.SC_CLK_TCK)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Warning: Failed to get SC_CLK_TCK from sysconf: %v. Using default value of 100 Hz.\n", err)
		return 100.0
	}

	if clkTck <= 0 || clkTck > 10000 {
		fmt.Fprintf(os.Stderr, "Warning: Got suspicious SC_CLK_TCK value %d. Using default value of 100 Hz.\n", clkTck)
		return 100.0
	}

	if os.Getenv("DEBUG") != "" {
		fmt.Fprintf(os.Stderr, "Debug: SC_CLK_TCK = %d Hz\n", clkTck)
	}

	return float64(clkTck)
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
	userCache[0] = "root"
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
		if info := detectContainerExtended(pid); info != nil {
			isContainer := true
			process.IsContainer = &isContainer
			process.ContainerID = info.ID
			process.ContainerName = info.Name
			process.ContainerType = info.Type

			// Kubernetes информация
			if info.IsKubernetes {
				process.K8sNamespace = info.PodNamespace
				process.K8sPodName = info.PodName
				process.K8sPodUID = info.PodUID
				process.K8sQoSClass = info.QoSClass
			}
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
					process.SwapBytes = swap * 1024
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
// CPU МОНИТОРИНГ
// ============================================================================

// calculateCPUUsage вычисляет CPU использование
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
	if timeDelta <= 0.01 {
		process.CPUPercent = 0.0
		return
	}

	// Дельта процессорного времени процесса в jiffies
	currentProcessTime := current.UTime + current.STime + current.CUTime + current.CSTime
	prevProcessTime := prev.UTime + prev.STime + prev.CUTime + prev.CSTime
	processCPUDelta := currentProcessTime - prevProcessTime

	// Конвертируем jiffies в секунды
	processCPUSeconds := float64(processCPUDelta) / clockTicksPerSec

	// ПРАВИЛЬНАЯ ФОРМУЛА: CPU% = (время_CPU_процесса / реальное_время) * 100
	cpuPercent := (processCPUSeconds / timeDelta) * 100.0

	// Нормализация
	if cpuPercent < 0 {
		cpuPercent = 0.0
	}

	if cpuPercent > 999.9 {
		cpuPercent = 999.9
	}

	process.CPUPercent = cpuPercent
	cpuStatsCache[process.PID] = current
}

// readProcessCPUStats читает CPU статистики процесса
func readProcessCPUStats(pid int) (CPUStats, error) {
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid))
	if err != nil {
		return CPUStats{}, err
	}

	fields := strings.Fields(string(data))
	if len(fields) < 22 {
		return CPUStats{}, fmt.Errorf("insufficient fields")
	}

	utime, err := strconv.ParseUint(fields[13], 10, 64)
	if err != nil {
		return CPUStats{}, fmt.Errorf("failed to parse utime: %w", err)
	}

	stime, err := strconv.ParseUint(fields[14], 10, 64)
	if err != nil {
		return CPUStats{}, fmt.Errorf("failed to parse stime: %w", err)
	}

	var cutime, cstime, starttime uint64

	if len(fields) > 15 {
		cutime, _ = strconv.ParseUint(fields[15], 10, 64)
	}

	if len(fields) > 16 {
		cstime, _ = strconv.ParseUint(fields[16], 10, 64)
	}

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
// ОПРЕДЕЛЕНИЕ КОНТЕЙНЕРОВ (ИСПРАВЛЕННАЯ ВЕРСИЯ ДЛЯ RKE2)
// ============================================================================

// detectContainerExtended определяет контейнер для процесса
func detectContainerExtended(pid int) *ContainerInfoExtended {
	file, err := os.Open(fmt.Sprintf("/proc/%d/cgroup", pid))
	if err != nil {
		return nil
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()

		if strings.TrimSpace(line) == "" {
			continue
		}

		// === Приоритет 1: KUBERNETES + containerd (systemd) ===
		if info := extractK8sContainerdSystemd(line); info != nil {
			// Пытаемся получить полное имя контейнера из crictl
			if info.ID != "" {
				if containerName := getContainerNameViaCrictl(info.ID); containerName != info.ID {
					info.Name = containerName
				}

				// Пытаемся получить K8s информацию из labels контейнера
				if labels := getContainerK8sLabels(info.ID); labels != nil {
					info.PodName = labels["io.kubernetes.pod.name"]
					info.PodNamespace = labels["io.kubernetes.pod.namespace"]
					info.ContainerName = labels["io.kubernetes.container.name"]
				}
			}

			// Если информацию не удалось получить из labels, пытаемся получить из pod metadata
			if (info.PodName == "" || info.PodNamespace == "") && info.PodUID != "" {
				if podInfo := getPodMetadataViaCrictl(info.PodUID); podInfo != nil {
					info.PodName = podInfo.Metadata.Name
					info.PodNamespace = podInfo.Metadata.Namespace
				} else if podInfo := getK8sPodInfoLocally(info.PodUID); podInfo != nil {
					// Fallback на локальную файловую систему
					info.PodName = podInfo.Name
					info.PodNamespace = podInfo.Namespace
				}
			}

			return info
		}

		// === Приоритет 2: KUBERNETES + containerd (cgroupsfs) ===
		if info := extractK8sContainerdCgroupsfs(line); info != nil {
			// Пытаемся получить полное имя контейнера из crictl
			if info.ID != "" {
				if containerName := getContainerNameViaCrictl(info.ID); containerName != info.ID {
					info.Name = containerName
				}

				// Пытаемся получить K8s информацию из labels контейнера
				if labels := getContainerK8sLabels(info.ID); labels != nil {
					info.PodName = labels["io.kubernetes.pod.name"]
					info.PodNamespace = labels["io.kubernetes.pod.namespace"]
					info.ContainerName = labels["io.kubernetes.container.name"]
				}
			}

			// Если информацию не удалось получить из labels, пытаемся получить из pod metadata
			if (info.PodName == "" || info.PodNamespace == "") && info.PodUID != "" {
				if podInfo := getPodMetadataViaCrictl(info.PodUID); podInfo != nil {
					info.PodName = podInfo.Metadata.Name
					info.PodNamespace = podInfo.Metadata.Namespace
				} else if podInfo := getK8sPodInfoLocally(info.PodUID); podInfo != nil {
					// Fallback на локальную файловую систему
					info.PodName = podInfo.Name
					info.PodNamespace = podInfo.Namespace
				}
			}

			return info
		}

		// === Приоритет 3: Docker ===
		if id := extractDockerID(line); id != "" {
			name := getDockerContainerName(id)
			return &ContainerInfoExtended{
				ID:           id,
				Name:         name,
				Type:         "docker",
				IsKubernetes: false,
			}
		}

		// === Приоритет 4: containerd (non-K8s) ===
		if info := extractContainerd(line); info != nil {
			return info
		}

		// === Приоритет 5: LXC ===
		if name := extractLXCName(line); name != "" {
			return &ContainerInfoExtended{
				ID:           name,
				Name:         name,
				Type:         "lxc",
				IsKubernetes: false,
			}
		}

		// === Приоритет 6: systemd machine ===
		if name := extractSystemdContainer(line); name != "" {
			return &ContainerInfoExtended{
				ID:           name,
				Name:         name,
				Type:         "systemd",
				IsKubernetes: false,
			}
		}
	}

	return nil
}

// ============================================================================
// KUBERNETES + cri-containerd ПАРСЕРЫ (SYSTEMD)
// ============================================================================

// extractK8sContainerdSystemd извлекает информацию из K8s pod cgroup (systemd)
func extractK8sContainerdSystemd(line string) *ContainerInfoExtended {
	originalLine := line
	line = strings.TrimPrefix(line, "0::")

	patterns := []struct {
		pattern    string
		isCgroupV2 bool
		qosGroupIdx int
		podGroupIdx int
		contGroupIdx int
	}{
		{
			`kubepods(?:-\w+)?\.slice/kubepods-(\w+)\.slice/kubepods-\w+-pod([a-f0-9_]+)\.slice/cri-containerd-([a-f0-9]+)\.scope`,
			strings.HasPrefix(originalLine, "0::"),
			1, 2, 3,
		},
		{
			`kubepods(?:-\w+)?\.slice/kubepods-(\w+)\.slice/kubepods-\w+-pod([a-f0-9_]+)\.slice/[^/]+\.scope`,
			strings.HasPrefix(originalLine, "0::"),
			1, 2, 0,
		},
	}

	for _, p := range patterns {
		re := regexp.MustCompile(p.pattern)
		matches := re.FindStringSubmatch(line)
		if matches == nil {
			continue
		}

		if len(matches) < 3 {
			continue
		}

		qosClass := matches[p.qosGroupIdx]
		podUID := matches[p.podGroupIdx]
		var containerID string

		if p.contGroupIdx > 0 && len(matches) > p.contGroupIdx {
			containerID = matches[p.contGroupIdx]
		}

		if len(containerID) > 12 {
			containerID = containerID[:12]
		} else if len(containerID) == 0 {
			containerID = extractSandboxContainerID(line)
		}

		return &ContainerInfoExtended{
			ID:           containerID,
			Name:         containerID,
			Type:         "cri-containerd",
			PodUID:       normalizePodUID(podUID),
			QoSClass:     normalizeQoSClass(qosClass),
			IsKubernetes: true,
			IsSandbox:    !strings.Contains(line, "cri-containerd-"),
		}
	}

	return nil
}

// ============================================================================
// KUBERNETES + cri-containerd ПАРСЕРЫ (CGROUPSFS)
// ============================================================================

// extractK8sContainerdCgroupsfs извлекает информацию из K8s pod cgroup (cgroupsfs)
func extractK8sContainerdCgroupsfs(line string) *ContainerInfoExtended {
	line = strings.TrimPrefix(line, "0::")

	patterns := []struct {
		regex       string
		qosIdx      int
		podIdx      int
		containerIdx int
	}{
		{
			`kubepods/(\w+)/pod([a-f0-9_]+)/cri-containerd-([a-f0-9]+)(?:\.scope)?`,
			1, 2, 3,
		},
		{
			`kubepods/(\w+)/pod([a-f0-9_]+)/([a-f0-9]{64})$`,
			1, 2, 3,
		},
		{
			`kubepods/(\w+)/pod([a-f0-9_]+)/([a-f0-9]{12,})`,
			1, 2, 3,
		},
	}

	for _, p := range patterns {
		re := regexp.MustCompile(p.regex)
		matches := re.FindStringSubmatch(line)
		if matches == nil || len(matches) <= p.containerIdx {
			continue
		}

		qosClass := matches[p.qosIdx]
		podUID := matches[p.podIdx]
		containerID := matches[p.containerIdx]

		if len(containerID) > 12 {
			containerID = containerID[:12]
		}

		return &ContainerInfoExtended{
			ID:           containerID,
			Name:         containerID,
			Type:         "cri-containerd",
			PodUID:       normalizePodUID(podUID),
			QoSClass:     normalizeQoSClass(qosClass),
			IsKubernetes: true,
			IsSandbox:    !strings.Contains(line, "cri-containerd-"),
		}
	}

	return nil
}

// getK8sPodInfoLocally получает информацию о поде из локальной файловой системы kubelet
func getK8sPodInfoLocally(podUID string) *K8sPodMetadata {
	if podUID == "" {
		return nil
	}

	cgroupUID := strings.ReplaceAll(podUID, "-", "_")

	paths := []string{
		fmt.Sprintf("/var/lib/rancher/rke2/kubelet/pods/%s", podUID),
		fmt.Sprintf("/var/lib/rancher/rke2/kubelet/pods/%s", cgroupUID),
		fmt.Sprintf("/var/lib/kubelet/pods/%s", podUID),
		fmt.Sprintf("/var/lib/kubelet/pods/%s", cgroupUID),
	}

	for _, basePath := range paths {
		if _, err := os.Stat(basePath); err != nil {
			continue
		}

		metadata := readPodMetadataFromPath(basePath, podUID)
		if metadata != nil {
			return metadata
		}
	}

	return nil
}

// readPodMetadataFromPath пытается прочитать метаданные пода из директории kubelet
func readPodMetadataFromPath(podPath string, podUID string) *K8sPodMetadata {
	specFiles := []string{
		filepath.Join(podPath, "pod.yaml"),
		filepath.Join(podPath, "pod.json"),
	}

	for _, specFile := range specFiles {
		if data, err := os.ReadFile(specFile); err == nil {
			var spec map[string]interface{}
			if err := json.Unmarshal(data, &spec); err == nil {
				if metadata, ok := spec["metadata"].(map[string]interface{}); ok {
					if name, ok := metadata["name"].(string); ok {
						if namespace, ok := metadata["namespace"].(string); ok {
							return &K8sPodMetadata{
								Name:      name,
								Namespace: namespace,
								UID:       podUID,
							}
						}
					}
				}
			}
		}
	}

	containersDir := filepath.Join(podPath, "containers")
	if entries, err := os.ReadDir(containersDir); err == nil && len(entries) > 0 {
		return &K8sPodMetadata{
			UID:       podUID,
			Namespace: extractNamespaceFromPodPath(podPath),
		}
	}

	if _, err := os.Stat(podPath); err == nil {
		return &K8sPodMetadata{
			UID:       podUID,
			Namespace: "default",
		}
	}

	return nil
}

// extractNamespaceFromPodPath пытается извлечь namespace из пути kubelet
func extractNamespaceFromPodPath(podPath string) string {
	containersDir := filepath.Join(podPath, "containers")
	if entries, err := os.ReadDir(containersDir); err == nil {
		for _, entry := range entries {
			containerPath := filepath.Join(containersDir, entry.Name())
			hostnameFile := filepath.Join(containerPath, "hostname")
			if data, err := os.ReadFile(hostnameFile); err == nil {
				hostname := strings.TrimSpace(string(data))
				parts := strings.Split(hostname, "-")
				if len(parts) > 1 {
					return parts[0]
				}
			}
		}
	}

	return "default"
}

// ============================================================================
// STANDALONE CONTAINERD ПАРСЕР
// ============================================================================

// extractContainerd извлекает информацию из standalone containerd
func extractContainerd(line string) *ContainerInfoExtended {
	patterns := []string{
		`/containerd/([a-f0-9]{64})`,
		`/containerd/([a-f0-9]{12,})`,
		`containerd-([a-f0-9]+)\.scope`,
		`-([a-f0-9]{12,})\.scope$`,
	}

	for _, pattern := range patterns {
		re := regexp.MustCompile(pattern)
		if matches := re.FindStringSubmatch(line); len(matches) > 1 {
			id := matches[1]
			if len(id) > 12 {
				id = id[:12]
			}

			return &ContainerInfoExtended{
				ID:           id,
				Name:         id,
				Type:         "containerd",
				IsKubernetes: false,
			}
		}
	}

	return nil
}

// ============================================================================
// УТИЛИТЫ ДЛЯ ПАРСИНГА KUBERNETES ИНФОРМАЦИИ
// ============================================================================

// normalizePodUID преобразует UID из cgroup в стандартный UUID формат
func normalizePodUID(cgroupUID string) string {
	parts := strings.Split(cgroupUID, "_")
	if len(parts) == 5 {
		return strings.Join(parts, "-")
	}

	return cgroupUID
}

// normalizeQoSClass преобразует QoS класс в стандартный формат
func normalizeQoSClass(qosStr string) string {
	switch strings.ToLower(strings.TrimSpace(qosStr)) {
	case "besteffort":
		return "BestEffort"
	case "burstable":
		return "Burstable"
	case "guaranteed":
		return "Guaranteed"
	default:
		return "Unknown"
	}
}

// extractSandboxContainerID извлекает ID sandbox/pause контейнера из пути
func extractSandboxContainerID(line string) string {
	patterns := []string{
		`/([a-f0-9]{64})$`,
		`/([a-f0-9]{12,})\.scope$`,
		`cri-containerd-([a-f0-9]+)`,
	}

	for _, pattern := range patterns {
		re := regexp.MustCompile(pattern)
		if matches := re.FindStringSubmatch(line); len(matches) > 1 {
			id := matches[1]
			if len(id) > 12 {
				id = id[:12]
			}

			return id
		}
	}

	return ""
}

// ============================================================================
// СТАРЫЕ ФУНКЦИИ ОПРЕДЕЛЕНИЯ КОНТЕЙНЕРОВ (совместимость)
// ============================================================================

// detectContainer определяет контейнер для процесса (adapter)
func detectContainer(pid int) *ContainerInfo {
	extInfo := detectContainerExtended(pid)
	if extInfo == nil {
		return nil
	}

	return &ContainerInfo{
		ID:   extInfo.ID,
		Name: extInfo.Name,
		Type: extInfo.Type,
	}
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

	// Фильтр Kubernetes
	if config.K8sOnly {
		if process.K8sNamespace == "" {
			return false
		}
	}

	// Фильтр K8s namespace
	if config.K8sNamespace != "" && process.K8sNamespace != config.K8sNamespace {
		return false
	}

	// Фильтр K8s QoS
	if config.K8sQoS != "" && process.K8sQoSClass != config.K8sQoS {
		return false
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

	switch strings.ToLower(filter) {
	case "cpu":
		return process.CPUPercent > 0
	case "memory", "mem":
		return process.MemoryBytes > 0
	case "swap":
		return process.SwapBytes > 0
	}

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

	if config.ShowKubernetes || config.ShowAll {
		headers = append(headers, "K8S_NS", "K8S_POD", "K8S_QOS")
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

		if config.ShowKubernetes || config.ShowAll {
			ns := process.K8sNamespace
			if ns == "" {
				ns = "-"
			}

			pod := process.K8sPodName
			if pod == "" {
				pod = "-"
			}

			qos := process.K8sQoSClass
			if qos == "" {
				qos = "-"
			}

			row = append(row, ns, pod, qos)
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
	data, err := json.MarshalIndent(filtered, "", " ")
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

		if config.ShowKubernetes || config.ShowAll {
			if process.K8sNamespace != "" {
				item["k8s_namespace"] = process.K8sNamespace
				item["k8s_pod_name"] = process.K8sPodName
				item["k8s_pod_uid"] = process.K8sPodUID
				item["k8s_qos_class"] = process.K8sQoSClass
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
		config.ShowAll || config.ContainerOnly || config.ShowKubernetes || config.K8sOnly
}

// ============================================================================
// CLI И MAIN
// ============================================================================

var rootCmd = &cobra.Command{
	Use:   "yaps",
	Short: "Yet another process monitor for Linux systems",
	Long: `A comprehensive process monitoring tool for Linux that provides detailed
information about running processes including CPU usage, memory consumption,
container detection, Kubernetes pod information, and much more.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		return runProcessMonitor()
	},
}

func init() {
	resourcesFlag := false
	rootCmd.PersistentFlags().BoolVarP(&config.ShowCPU, "show-cpu", "c", false, "Show CPU utilization")
	rootCmd.PersistentFlags().BoolVarP(&config.ShowMemory, "show-mem", "m", false, "Show memory usage")
	rootCmd.PersistentFlags().BoolVarP(&config.ShowSwap, "show-swap", "s", false, "Show swap usage")
	rootCmd.PersistentFlags().BoolVarP(&config.ShowCommand, "show-cmd", "C", false, "Show command line")
	rootCmd.PersistentFlags().BoolVarP(&config.ShowUser, "show-user", "u", false, "Show user")
	rootCmd.PersistentFlags().BoolVarP(&resourcesFlag, "resources", "r", false, "Show CPU, memory, and swap")
	rootCmd.PersistentFlags().BoolVar(&config.ShowContainer, "show-container", false, "Show container flag")
	rootCmd.PersistentFlags().BoolVar(&config.ShowContainerID, "container-id", false, "Show container ID")
	rootCmd.PersistentFlags().BoolVar(&config.ShowContainerName, "container-name", false, "Show container name")
	rootCmd.PersistentFlags().BoolVar(&config.ShowKubernetes, "show-k8s", false, "Show Kubernetes pod and namespace info")
	rootCmd.PersistentFlags().BoolVar(&config.K8sOnly, "k8s-only", false, "Show only processes from Kubernetes pods")
	rootCmd.PersistentFlags().StringVar(&config.K8sNamespace, "k8s-namespace", "", "Filter by Kubernetes namespace")
	rootCmd.PersistentFlags().StringVar(&config.K8sQoS, "k8s-qos", "", "Filter by QoS class (BestEffort, Burstable, Guaranteed)")
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
			!config.ShowContainerID && !config.ShowContainerName && !config.ShowKubernetes {
			config.ShowAll = true
		}
	}

	versionCmd := &cobra.Command{
		Use:   "version",
		Short: "Print version information",
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Println("yaps - Process Monitor v1.1.0 (with crictl CRI integration and Kubernetes RKE2 support)")
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
