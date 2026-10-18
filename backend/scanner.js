const { runMockScan } = require("./mockScanner");

// When @Graicei7's scanner is ready, only this function changes.
function runScan(target) {
  return new Promise((resolve) => {
    setTimeout(() => resolve(runMockScan(target)), 2000);
  });
}

module.exports = { runScan };