const statusChecker = require("../services/statusChecker");

exports.getStatus = (req, res) => {
    res.json(statusChecker.getStatusSummary());
};
