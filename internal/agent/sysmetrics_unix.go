//go:build !windows

package agent

import (
	"os"
	"runtime"
	"strconv"
	"strings"
)

func runtimeNumCPU() int { return runtime.NumCPU() }

func systemMetrics() (float64, int64, int64) { return linuxMetrics() }

func netCounters() (rx, tx int64) { return linuxNetCounters() }

// linuxMetrics 读 /proc/meminfo；CPU% 需要连续采样，这里用 loadavg 近似（负载/核数*100 截断）。
func linuxMetrics() (cpuPct float64, memUsed, memTotal int64) {
	data, err := os.ReadFile("/proc/loadavg")
	if err == nil {
		fields := strings.Fields(string(data))
		if len(fields) > 0 {
			load, _ := strconv.ParseFloat(fields[0], 64)
			cores := float64(runtimeNumCPU())
			if cores > 0 {
				cpuPct = load / cores * 100
				if cpuPct > 100 {
					cpuPct = 100
				}
			}
		}
	}
	data, err = os.ReadFile("/proc/meminfo")
	if err == nil {
		for _, line := range strings.Split(string(data), "\n") {
			fields := strings.Fields(line)
			if len(fields) < 2 {
				continue
			}
			v, _ := strconv.ParseInt(fields[1], 10, 64)
			switch fields[0] {
			case "MemTotal:":
				memTotal = v * 1024
			case "MemAvailable:":
				memUsed = memTotal - v*1024
			}
		}
	}
	return
}

func linuxNetCounters() (rx, tx int64) {
	data, err := os.ReadFile("/proc/net/dev")
	if err != nil {
		return 0, 0
	}
	for _, line := range strings.Split(string(data), "\n") {
		idx := strings.Index(line, ":")
		if idx < 0 {
			continue
		}
		iface := strings.TrimSpace(line[:idx])
		if isVirtualIface(iface) {
			continue
		}
		fields := strings.Fields(line[idx+1:])
		if len(fields) >= 9 {
			v, _ := strconv.ParseInt(fields[0], 10, 64)
			rx += v
			v, _ = strconv.ParseInt(fields[8], 10, 64)
			tx += v
		}
	}
	return
}

func isVirtualIface(name string) bool {
	switch {
	case name == "lo", name == "lo0":
		return true
	case len(name) > 3 && name[:3] == "veth":
		return true
	case len(name) > 4 && name[:4] == "docker":
		return true
	case len(name) > 2 && name[:2] == "br":
		return true
	}
	return false
}
