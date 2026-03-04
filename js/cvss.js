// CVSS v3.1 Metric Weight Constants
const Weight = {
    AV: { N: 0.85, A: 0.62, L: 0.55, P: 0.2 },
    AC: { H: 0.44, L: 0.77 },
    PR: {
        U: { N: 0.85, L: 0.62, H: 0.27 }, // Unchanged Scope
        C: { N: 0.85, L: 0.68, H: 0.5 }   // Changed Scope
    },
    UI: { N: 0.85, R: 0.62 },
    S:  { U: 6.42, C: 7.52 },
    C:  { N: 0, L: 0.22, H: 0.56 },
    I:  { N: 0, L: 0.22, H: 0.56 },
    A:  { N: 0, L: 0.22, H: 0.56 }
};

/**
 * Rounds up to exactly one decimal place.
 * Following CVSS v3.1 standard round up logic.
 */
function roundUp1(d) {
    // Math.round(d * 100000) / 100000 is needed to avoid JS floating point errors
    return Math.ceil(Math.round(d * 100000) / 10000) / 10;
}

/**
 * Calculates CVSS v3.1 Base Score from metrics object
 * @param {Object} metrics - e.g. {AV: 'N', AC: 'L', PR: 'N', UI: 'N', S: 'U', C: 'H', I: 'H', A: 'H'}
 * @returns {Object} { score: string, severity: string, vector: string, isComplete: boolean }
 */
export function calculateCVSS(metrics) {
    const defaultMetrics = { AV: '_', AC: '_', PR: '_', UI: '_', S: '_', C: '_', I: '_', A: '_' };
    const m = { ...defaultMetrics, ...metrics };
    
    // Generate vector string
    const vector = `CVSS:3.1/AV:${m.AV}/AC:${m.AC}/PR:${m.PR}/UI:${m.UI}/S:${m.S}/C:${m.C}/I:${m.I}/A:${m.A}`;
    
    // Check if all metrics are selected
    const isComplete = !Object.values(m).includes('_');
    
    if (!isComplete) {
        return { score: '0.0', severity: 'None', vector, isComplete: false };
    }

    // ISCBase calculation
    const iscBase = 1 - ((1 - Weight.C[m.C]) * (1 - Weight.I[m.I]) * (1 - Weight.A[m.A]));
    
    let iss;
    if (m.S === 'U') {
        iss = Weight.S.U * iscBase;
    } else {
        iss = Weight.S.C * (iscBase - 0.029) - 3.25 * Math.pow(iscBase - 0.02, 15);
    }
    
    // Exploitability calculation
    const prWeight = m.S === 'U' ? Weight.PR.U[m.PR] : Weight.PR.C[m.PR];
    const exploitability = 8.22 * Weight.AV[m.AV] * Weight.AC[m.AC] * prWeight * Weight.UI[m.UI];
    
    // Base Score calculation
    let baseScore = 0;
    
    if (iss <= 0) {
        baseScore = 0;
    } else {
        if (m.S === 'U') {
            baseScore = roundUp1(Math.min(iss + exploitability, 10));
        } else {
            baseScore = roundUp1(Math.min(1.08 * (iss + exploitability), 10));
        }
    }
    
    // Determine severity mapping
    let severity = 'None';
    if (baseScore === 0) {
        severity = 'None';
    } else if (baseScore >= 0.1 && baseScore <= 3.9) {
        severity = 'Low';
    } else if (baseScore >= 4.0 && baseScore <= 6.9) {
        severity = 'Medium';
    } else if (baseScore >= 7.0 && baseScore <= 8.9) {
        severity = 'High';
    } else if (baseScore >= 9.0 && baseScore <= 10.0) {
        severity = 'Critical';
    }
    
    return {
        score: baseScore.toFixed(1),
        severity,
        vector,
        isComplete: true
    };
}
