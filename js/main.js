import { calculateCVSS } from './cvss.js';
import { calculateCVSS4 } from './cvss4.js';

document.addEventListener('DOMContentLoaded', () => {
    const radioInputs = document.querySelectorAll('input[type="radio"]');
    const scoreValue = document.getElementById('score-value');
    const scoreSeverity = document.getElementById('score-severity');
    const vectorString = document.getElementById('vector-string');
    const instructionText = document.getElementById('instruction-text');
    const scoreCard = document.getElementById('score-card');

    // Toggle Elements
    const btnV3 = document.getElementById('btn-v3');
    const btnV4 = document.getElementById('btn-v4');
    const containerV3 = document.getElementById('container-v3');
    const containerV4 = document.getElementById('container-v4');
    const versionLabel = document.getElementById('version-label');

    // State to store current selected metrics for both versions
    const currentMetricsV3 = {};
    const currentMetricsV4 = {};
    let activeVersion = 'v3'; // 'v3' or 'v4'

    // Initial UI Setup: Make sure missing counts show up properly
    updateUI();

    // Initialize radio listeners
    radioInputs.forEach(input => {
        input.addEventListener('change', (e) => {
            const metricName = e.target.name;
            const metricValue = e.target.value;

            // Map to correct state based on prefix
            if (metricName.startsWith('v4_')) {
                const pureName = metricName.replace('v4_', '');
                currentMetricsV4[pureName] = metricValue;
            } else {
                currentMetricsV3[metricName] = metricValue;
            }

            updateUI();
        });
    });

    // Toggle Listeners
    btnV3.addEventListener('click', () => {
        activeVersion = 'v3';
        btnV3.classList.add('active');
        btnV4.classList.remove('active');
        containerV3.style.display = 'block';
        containerV4.style.display = 'none';
        versionLabel.textContent = 'CVSS v3.1';
        updateUI();
    });

    btnV4.addEventListener('click', () => {
        activeVersion = 'v4';
        btnV4.classList.add('active');
        btnV3.classList.remove('active');
        containerV4.style.display = 'block';
        containerV3.style.display = 'none';
        versionLabel.textContent = 'CVSS v4.0';
        updateUI();
    });

    function updateUI() {
        let result;
        let missingCount = 0;

        if (activeVersion === 'v3') {
            result = calculateCVSS(currentMetricsV3);
            missingCount = 8 - Object.keys(currentMetricsV3).length;
        } else {
            result = calculateCVSS4(currentMetricsV4);
            missingCount = 11 - Object.keys(currentMetricsV4).length;
        }

        // Update Vector
        vectorString.textContent = result.vector;

        if (result.isComplete) {
            instructionText.style.display = 'none';
            scoreValue.textContent = result.score;
            scoreSeverity.textContent = result.severity;

            // Update styling classes
            scoreCard.className = 'score-card'; // reset
            scoreCard.classList.add(`sev-${result.severity.toLowerCase()}`);

            // Update accent color of radio buttons based on severity
            document.documentElement.style.setProperty('--accent-blue', `var(--sev-${result.severity.toLowerCase()})`);
        } else {
            // Still incomplete
            instructionText.style.display = 'block';
            instructionText.textContent = `Masih ada opsi yang belum dipilih. (${missingCount} tersisa)`;

            scoreValue.textContent = '0.0';
            scoreSeverity.textContent = 'None';
            scoreCard.className = 'score-card'; // reset
        }
    }
});
