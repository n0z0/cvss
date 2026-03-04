/**
 * Calculates CVSS v4.0 Base Score using official FIRST.org Logic.
 * Requires cvss_lookup_global, maxSeverity, macroVector, and cvss_score to be loaded in the global scope.
 */
export function calculateCVSS4(metrics) {
    const defaultBase = { AV: '_', AC: '_', AT: '_', PR: '_', UI: '_', VC: '_', VI: '_', VA: '_', SC: '_', SI: '_', SA: '_' };
    const defaultThreatEnv = { E: 'X', CR: 'X', IR: 'X', AR: 'X' };
    const defaultModified = { MAV: 'X', MAC: 'X', MAT: 'X', MPR: 'X', MUI: 'X', MVC: 'X', MVI: 'X', MVA: 'X', MSC: 'X', MSI: 'X', MSA: 'X' };

    // Combine base inputs with explicit 'X' (Not Defined) for all advanced metrics required by FIRST.org math engine
    const m = { ...defaultBase, ...defaultThreatEnv, ...defaultModified, ...metrics };

    // Check if all metrics are selected
    const isComplete = !Object.values(m).includes('_');
    const vector = `CVSS:4.0/AV:${m.AV}/AC:${m.AC}/AT:${m.AT}/PR:${m.PR}/UI:${m.UI}/VC:${m.VC}/VI:${m.VI}/VA:${m.VA}/SC:${m.SC}/SI:${m.SI}/SA:${m.SA}`;

    if (!isComplete) {
        return { score: '0.0', severity: 'None', vector, isComplete: false };
    }

    // 1. Calculate the macro vector using official FIRST logic
    const mv = macroVector(m);

    // 2. Calculate the exact standard CVSS 4.0 score using the official FIRST equation logic
    const exactScore = cvss_score(m, cvssLookup_global, maxSeverity, mv);

    // Determine severity mapping
    let severity = 'None';
    if (exactScore === 0) {
        severity = 'None';
    } else if (exactScore >= 0.1 && exactScore <= 3.9) {
        severity = 'Low';
    } else if (exactScore >= 4.0 && exactScore <= 6.9) {
        severity = 'Medium';
    } else if (exactScore >= 7.0 && exactScore <= 8.9) {
        severity = 'High';
    } else if (exactScore >= 9.0 && exactScore <= 10.0) {
        severity = 'Critical';
    }

    return {
        score: exactScore.toFixed(1),
        severity,
        vector,
        isComplete: true
    };
}
