import { calculateCVSS } from './js/cvss.js';
import { calculateCVSS4 } from './js/cvss4.js';

console.log("Testing CVSS 3.1:");
const res3 = calculateCVSS({ AV: 'N', AC: 'L', PR: 'N', UI: 'N', S: 'C', C: 'H', I: 'H', A: 'H' });
console.log(res3);

console.log("\nTesting CVSS 4.0 (Max Score):");
const res4_max = calculateCVSS4({ AV: 'N', AC: 'L', AT: 'N', PR: 'N', UI: 'N', VC: 'H', VI: 'H', VA: 'H', SC: 'H', SI: 'H', SA: 'H' });
console.log(res4_max);

console.log("\nTesting CVSS 4.0 (Attack Requirements: Present):");
const res4_present = calculateCVSS4({ AV: 'N', AC: 'L', AT: 'P', PR: 'N', UI: 'N', VC: 'H', VI: 'H', VA: 'H', SC: 'H', SI: 'H', SA: 'H' });
console.log(res4_present);
