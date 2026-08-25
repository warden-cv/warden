package server

import (
	"bufio"
	"encoding/json"
	"os"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

type usagePair struct {
	Total uint64 `json:"total"`
	Used  uint64 `json:"used"`
}

type monitorSnapshot struct {
	Timestamp  int64      `json:"timestamp"`
	Hostname   string     `json:"hostname"`
	Uptime     float64    `json:"uptime"`
	Load       [3]float64 `json:"load"`
	CPU        float64    `json:"cpu"`
	Memory     usagePair  `json:"memory"`
	Disk       usagePair  `json:"disk"`
	Processes  int        `json:"processes"`
	GoRoutines int        `json:"goRoutines"`
}

var lastCPU struct {
	sync.Mutex
	total, idle uint64
	at          time.Time
}

func monitor(root string) monitorSnapshot {
	var s monitorSnapshot
	s.Timestamp = time.Now().Unix()
	s.Hostname, _ = os.Hostname()
	s.GoRoutines = runtime.NumGoroutine()
	if b, e := os.ReadFile("/proc/uptime"); e == nil {
		f := strings.Fields(string(b))
		s.Uptime, _ = strconv.ParseFloat(f[0], 64)
	}
	if b, e := os.ReadFile("/proc/loadavg"); e == nil {
		f := strings.Fields(string(b))
		for i := 0; i < 3 && i < len(f); i++ {
			s.Load[i], _ = strconv.ParseFloat(f[i], 64)
		}
	}
	s.CPU = cpuUsage()
	readMem(&s)
	var st syscall.Statfs_t
	if syscall.Statfs(root, &st) == nil {
		s.Disk.Total = st.Blocks * uint64(st.Bsize)
		free := st.Bavail * uint64(st.Bsize)
		s.Disk.Used = s.Disk.Total - free
	}
	if ds, e := os.ReadDir("/proc"); e == nil {
		for _, d := range ds {
			if d.IsDir() {
				if _, e := strconv.Atoi(d.Name()); e == nil {
					s.Processes++
				}
			}
		}
	}
	return s
}
func cpuUsage() float64 {
	lastCPU.Lock()
	defer lastCPU.Unlock()
	f, e := os.Open("/proc/stat")
	if e != nil {
		return 0
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	if !sc.Scan() {
		return 0
	}
	p := strings.Fields(sc.Text())
	if len(p) < 5 {
		return 0
	}
	var vals []uint64
	for _, v := range p[1:] {
		n, _ := strconv.ParseUint(v, 10, 64)
		vals = append(vals, n)
	}
	var total uint64
	for _, v := range vals {
		total += v
	}
	idle := vals[3]
	if len(vals) > 4 {
		idle += vals[4]
	}
	dt := total - lastCPU.total
	di := idle - lastCPU.idle
	lastCPU.total, lastCPU.idle = total, idle
	if dt == 0 {
		return 0
	}
	return 100 * float64(dt-di) / float64(dt)
}
func readMem(s *monitorSnapshot) {
	b, e := os.ReadFile("/proc/meminfo")
	if e != nil {
		return
	}
	m := map[string]uint64{}
	for _, ln := range strings.Split(string(b), "\n") {
		f := strings.Fields(ln)
		if len(f) >= 2 {
			v, _ := strconv.ParseUint(f[1], 10, 64)
			m[strings.TrimSuffix(f[0], ":")] = v * 1024
		}
	}
	s.Memory.Total = m["MemTotal"]
	avail := m["MemAvailable"]
	if s.Memory.Total > avail {
		s.Memory.Used = s.Memory.Total - avail
	}
}
func jsonBytes(v any) []byte { b, _ := json.Marshal(v); return b }
