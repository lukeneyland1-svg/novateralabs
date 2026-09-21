const complianceLog = require("../services/complianceLog");

exports.exportLog = (req, res) => {
    try {
        const { from, to } = req.query;
        const rows = complianceLog.getComplianceLog(req.session.userId, { from, to });
        const csv = complianceLog.exportAsCSV(rows);

        res.setHeader("Content-Type", "text/csv");
        res.setHeader("Content-Disposition", `attachment; filename="novateralabs-compliance-log.csv"`);
        res.send(csv);
    } catch (err) {
        console.error("Compliance export error:", err);
        res.status(500).json({ error: "Internal Server Error" });
    }
};
