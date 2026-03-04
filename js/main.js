import { calculateCVSS } from './cvss.js';

document.addEventListener('DOMContentLoaded', () => {
    const radioInputs = document.querySelectorAll('input[type="radio"]');
    const scoreValue = document.getElementById('score-value');
    const scoreSeverity = document.getElementById('score-severity');
    const vectorString = document.getElementById('vector-string');
    const instructionText = document.getElementById('instruction-text');
    const scoreCard = document.getElementById('score-card');

    // State to store current selected metrics
    const currentMetrics = {};

    // Initialize radio listeners
    radioInputs.forEach(input => {
        input.addEventListener('change', (e) => {
            const metricName = e.target.name;
            const metricValue = e.target.value;

            // Update state
            currentMetrics[metricName] = metricValue;

            // Calculate new score
            updateUI();
        });
    });

    function updateUI() {
        const result = calculateCVSS(currentMetrics);

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

            const missingCount = 8 - Object.keys(currentMetrics).length;
            instructionText.textContent = `Masih ada ${missingCount} opsi dasar yang harus dipilih.`;

            scoreValue.textContent = '0.0';
            scoreSeverity.textContent = 'None';
            scoreCard.className = 'score-card'; // reset
        }
    }
});
