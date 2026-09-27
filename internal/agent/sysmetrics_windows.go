//go:build windows

package agent

import (
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"time"
)

func systemMetrics() (float64, int64, int64) { return windowsMetrics() }

func netCounters() (rx, tx int64) { return windowsNetCounters() }

// M13: PowerShell 进程创建开销大（数百 ms / 数十 MB），结果缓存复用，
// 采样周期实际拉长到 minInterval（速度曲线变粗但资源占用可控）。
var (
	metricsMu   sync.Mutex
	metricsAt   time.Time
	metricsVals [3]float64 // cpu, memUsed, memTotal
	netMu       sync.Mutex
	netAt       time.Time
	netVals     [2]int64 // rx, tx
)

const metricsMinInterval = 15 * time.Second
const netMinInterval = 5 * time.Second

func windowsMetrics() (cpuPct float64, memUsed, memTotal int64) {
	metricsMu.Lock()
	defer metricsMu.Unlock()
	if time.Since(metricsAt) < metricsMinInterval {
		return metricsVals[0], int64(metricsVals[1]), int64(metricsVals[2])
	}
	out, err := exec.Command("powershell", "-NoProfile", "-Command",
		"$os=Get-CimInstance Win32_OperatingSystem; $cpu=(Get-CimInstance Win32_Processor | Measure-Object -Property LoadPercentage -Average).Average; \"$cpu `t $($os.TotalVisibleMemorySize) `t $($os.FreePhysicalMemory)\"").Output()
	if err == nil {
		parts := strings.Fields(string(out))
		if len(parts) >= 3 {
			cpu, _ := strconv.ParseFloat(parts[0], 64)
			totalKB, _ := strconv.ParseInt(parts[1], 10, 64)
			freeKB, _ := strconv.ParseInt(parts[2], 10, 64)
			metricsVals = [3]float64{cpu, float64(totalKB * 1024), float64((totalKB - freeKB) * 1024)}
			metricsAt = time.Now()
		}
	}
	return metricsVals[0], int64(metricsVals[1]), int64(metricsVals[2])
}

func windowsNetCounters() (rx, tx int64) {
	netMu.Lock()
	defer netMu.Unlock()
	if time.Since(netAt) < netMinInterval {
		return netVals[0], netVals[1]
	}
	out, err := exec.Command("powershell", "-NoProfile", "-Command",
		"(Get-NetAdapterStatistics | Measure-Object -Property ReceivedBytes, SentBytes -Sum | ForEach-Object Sum) -join ' '").Output()
	if err == nil {
		parts := strings.Fields(string(out))
		if len(parts) >= 2 {
			rx, _ = strconv.ParseInt(parts[0], 10, 64)
			tx, _ = strconv.ParseInt(parts[1], 10, 64)
			netVals = [2]int64{rx, tx}
			netAt = time.Now()
		}
	}
	return netVals[0], netVals[1]
}
