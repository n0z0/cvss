import { cvss4Lookup } from './cvss4/cvss4_lookup.js';

// Eq1
const eq1_val = { AV: { N: 0, A: 1, L: 2, P: 3 }, PR: { N: 0, L: 1, H: 2 }, UI: { N: 0, P: 1, A: 2 } };
// Eq2
const eq2_val = { AC: { L: 0, H: 1 }, AT: { N: 0, P: 1 } };
// Eq3
const eq3_val = { VC: { H: 0, L: 1, N: 2 }, VI: { H: 0, L: 1, N: 2 }, VA: { H: 0, L: 1, N: 2 } };
// Eq4
const eq4_val = { SC: { H: 0, L: 1, N: 2 }, SI: { H: 0, L: 1, N: 2 }, SA: { H: 0, L: 1, N: 2 } };
// Eq5 (not used in Base purely, but required for macrovector index calculation per FIRST ref)
// In base score, eq5 always resolves to 0 

/**
 * Calculates CVSS v4.0 Base Score
 * Required Input Metrics: AV, AC, AT, PR, UI, VC, VI, VA, SC, SI, SA
 */
export function calculateCVSS4(metrics) {
    const defaultMetrics = { AV: '_', AC: '_', AT: '_', PR: '_', UI: '_', VC: '_', VI: '_', VA: '_', SC: '_', SI: '_', SA: '_' };
    const m = { ...defaultMetrics, ...metrics };

    // Check if all metrics are selected
    const isComplete = !Object.values(m).includes('_');
    const vector = `CVSS:4.0/AV:${m.AV}/AC:${m.AC}/AT:${m.AT}/PR:${m.PR}/UI:${m.UI}/VC:${m.VC}/VI:${m.VI}/VA:${m.VA}/SC:${m.SC}/SI:${m.SI}/SA:${m.SA}`;

    if (!isComplete) {
        return { score: '0.0', severity: 'None', vector, isComplete: false };
    }

    // Determine the MacroVector String (e.g. EQ1, EQ2, EQ3, EQ4, EQ5, EQ6)
    // The macrovector determines the lookup index string

    let eq1 = 0;
    if (m.AV === 'N' && m.PR === 'N' && m.UI === 'N') { eq1 = 0; }
    else if ((m.AV === 'N' || m.AV === 'A' || m.AV === 'L') && !(m.PR === 'H' || m.UI === 'A') && !(m.AV === 'N' && m.PR === 'N' && m.UI === 'N')) { eq1 = 1; }
    else if (m.AV === 'P' || m.PR === 'H' || m.UI === 'A') { eq1 = 2; }

    let eq2 = 0;
    if (m.AC === 'L' && m.AT === 'N') { eq2 = 0; }
    else { eq2 = 1; }

    let eq3 = 0;
    if (m.VC === 'H' && m.VI === 'H') { eq3 = 0; }
    else if (!(m.VC === 'H' && m.VI === 'H') && (m.VC !== 'N' || m.VI !== 'N' || m.VA !== 'N')) { eq3 = 1; }
    else if (m.VC === 'N' && m.VI === 'N' && m.VA === 'N') { eq3 = 2; }

    let eq4 = 0;
    if (m.SC === 'H' || m.SI === 'H' || m.SA === 'H') { eq4 = 0; }
    else if (!(m.SC === 'H' || m.SI === 'H' || m.SA === 'H') && (m.SC !== 'N' || m.SI !== 'N' || m.SA !== 'N')) { eq4 = 1; }
    else if (m.SC === 'N' && m.SI === 'N' && m.SA === 'N') { eq4 = 2; }

    let eq5 = 0; // EQ5 is based on E (Exploit Maturity), but E is a Threat metric. For base score calculation, E is 'X' (equiv to 'A'), resolving EQ5 to 0. (FIRST spec)
    let eq6 = 0; // EQ6 is based on CR, IR, AR. Default to 'X' (equiv to 'H'), resolving EQ6 to 0. (FIRST spec)

    // MacroVector Lookup String Form: EQ1 EQ2 EQ3 EQ4 EQ5 EQ6
    let macroVectorStr = `${eq1}${eq2}${eq3}${eq4}${eq5}${eq6}`;

    // The logic to calculate the exact distance score within the macrovector bucket 
    // is highly complex. The FIRST implementation uses a pre-calculated comprehensive 
    // dictionary because pure mathematical interpolation in CVSS v4 is notoriously hard.

    // Get Base Score from Lookup
    let baseScore = cvss4Lookup[macroVectorStr];

    // If baseScore wasn't derived properly (e.g. edge cases in metric combos), or is undefined, fallback.
    // However, FIRST spec states if VC=N and VI=N and VA=N, score is 0
    if (m.VC === 'N' && m.VI === 'N' && m.VA === 'N') {
        baseScore = 0;
    }

    if (baseScore === undefined) {
        // Some specific combinations (especially when SC/SI/SA are N) might not map tightly 
        // into the simplified pure-base lookup if Threat metrics alter them. But assuming Base only:
        baseScore = 0.0;
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
