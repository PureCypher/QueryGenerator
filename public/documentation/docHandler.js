import { sanitizeInput } from '../utils/sanitization.js';

export function updateDocumentation(template) {
    const queryExplanation = document.getElementById('queryExplanation');
    if (template) {
        const sanitizedTitle = sanitizeInput(template.title);
        const sanitizedDescription = sanitizeInput(template.description);
        
        queryExplanation.innerHTML = `
            <p><strong>${sanitizedTitle}</strong></p>
            <p>${sanitizedDescription}</p>
            <h4>Parameters:</h4>
            <ul>
                ${template.parameters.map(param => 
                    `<li><strong>${sanitizeInput(param.field)}</strong> ${sanitizeInput(param.operator)} ${sanitizeInput(param.value)}</li>`
                ).join('')}
            </ul>
        `;
    } else {
        queryExplanation.innerHTML = '';
    }
}
