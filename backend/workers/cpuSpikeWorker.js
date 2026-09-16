const { workerData } = require("worker_threads");

const endTime = Date.now() + workerData.durationSeconds * 1000;

// Deliberately CPU-intensive, but strictly time-bounded — stops automatically.
while (Date.now() < endTime) {
    Math.sqrt(Math.random() * 999999);
}
