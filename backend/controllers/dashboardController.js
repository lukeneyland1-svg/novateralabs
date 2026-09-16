const si = require("systeminformation");
const os = require("os");
/* ============================================================
   GET DASHBOARD DATA
============================================================ */
exports.getDashboardData = async (req, res) => {
    try {
        // Gather all system info in parallel
        const [
            osInfo,
            cpuLoad,
            mem,
            disk,
            temp,
            net
        ] = await Promise.all([
            si.osInfo(),
            si.currentLoad(),
            si.mem(),
            si.fsSize(),
            si.cpuTemperature(),
            si.networkStats()
        ]);

        /* ============================================================
           SYSTEM SECTION (matches frontend)
        ============================================================ */
        const system = {
            os: osInfo.distro,
            uptime: (process.uptime() / 60).toFixed(1) + " min",
            cpu_load: cpuLoad.currentLoad,
            ram_usage: (mem.used / mem.total) * 100,
            battery: "N/A",
            load_avg: os.loadavg()[0],
            cpu_count: os.cpus().length
        };

        /* ============================================================
           METRICS SECTION (matches frontend)
        ============================================================ */
        const metrics = {
            cpu: {
                user_percent: cpuLoad.currentLoadUser,
                system_percent: cpuLoad.currentLoadSystem,
                idle_percent: 100 - cpuLoad.currentLoad
            },
            memory: {
                total: mem.total,
                used: mem.used,
                free: mem.free,
                node_heap_used: process.memoryUsage().heapUsed,
                node_heap_total: process.memoryUsage().heapTotal
            },
            disk: {
                total: disk[0].size,
                used: disk[0].used,
                free: disk[0].available
            },
            temperature: {
                cpu: temp.main || 0
            },
            network: {
                rx: net[0].rx_bytes,
                tx: net[0].tx_bytes
            }
        };

        res.json({ system, metrics });

    } catch (err) {
        console.error("Dashboard API error:", err);
        res.status(500).json({ error: "Internal Server Error" });
    }
};
