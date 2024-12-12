import { sanitizeInput } from '../utils/sanitization.js';
import { queryLanguages } from '../config/queryConfig.js';
import { state } from '../state/appState.js';

export function generateTimeRangeString() {
    const timeRange = sanitizeInput(document.getElementById('timeRange').value);
    if (timeRange === 'custom') {
        const start = sanitizeInput(document.getElementById('startTime').value);
        const end = sanitizeInput(document.getElementById('endTime').value);
        return `earliest="${start}" latest="${end}"`;
    }

    const timeMap = {
        '15m': 'earliest=-15m',
        '1h': 'earliest=-1h',
        '24h': 'earliest=-24h',
        '7d': 'earliest=-7d',
        '30d': 'earliest=-30d'
    };

    return timeMap[timeRange] || 'earliest=-24h';
}

export function getParameters() {
    const params = [];
    document.querySelectorAll('.parameter-row').forEach(row => {
        const field = sanitizeInput(row.querySelector('.field-name').value);
        const operator = sanitizeInput(row.querySelector('.operator').value);
        const value = sanitizeInput(row.querySelector('.field-value').value);
        
        if (field && value) {
            params.push({ field, operator, value });
        }
    });
    return params;
}

export function updateQueryOutput() {
    const queryOutput = document.getElementById('queryOutput');
    const language = sanitizeInput(document.getElementById('queryLanguage').value);
    const config = queryLanguages[language];
    const sources = state.getSelectedSources();
    const parameters = getParameters();
    const timeRange = generateTimeRangeString();

    let query = config.template;
    
    const sourcesStr = sources.length > 0 ? sources.join(` ${config.sourceJoin} `) : '*';
    query = query.replace('{sources}', sourcesStr);

    const conditions = parameters.map(param => {
        const operator = config.operators[param.operator];
        return `${param.field} ${operator} ${param.value}`;
    }).join(` ${config.conditionJoin} `);
    
    query = query.replace('{conditions}', conditions || '*');
    query = query.replace('{timeRange}', timeRange);

    queryOutput.textContent = query;
    updateOptimizationSuggestions(query, parameters);
}

export function updateOptimizationSuggestions(query, parameters) {
    const suggestions = document.getElementById('optimizationSuggestions');
    const suggestionsList = [];

    if (query.length > 1000) {
        suggestionsList.push('Consider breaking down the query into smaller, more focused queries for better performance.');
    }

    if (query.includes('*') && !query.includes('\\*')) {
        suggestionsList.push('Using wildcards might impact performance. Consider using more specific filters when possible.');
    }

    if (parameters.length > 0 && !parameters.some(p => p.field.toLowerCase().includes('time'))) {
        suggestionsList.push('Consider adding a time-based filter to improve query performance.');
    }

    suggestions.innerHTML = suggestionsList.length > 0
        ? `<ul>${suggestionsList.map(s => `<li>${sanitizeInput(s)}</li>`).join('')}</ul>`
        : '<p>No optimization suggestions available.</p>';
}

export function validateQuery() {
    const queryOutput = document.getElementById('queryOutput');
    const query = queryOutput.textContent;
    const language = sanitizeInput(document.getElementById('queryLanguage').value);
    
    let isValid = true;
    let message = '';

    if (!query.trim()) {
        isValid = false;
        message = 'Query cannot be empty';
    }

    const brackets = query.match(/[\[\](){}]/g) || [];
    const stack = [];
    for (const bracket of brackets) {
        if (['[', '(', '{'].includes(bracket)) {
            stack.push(bracket);
        } else {
            const last = stack.pop();
            if (
                (bracket === ']' && last !== '[') ||
                (bracket === ')' && last !== '(') ||
                (bracket === '}' && last !== '{')
            ) {
                isValid = false;
                message = 'Unmatched brackets or parentheses';
                break;
            }
        }
    }
    if (stack.length > 0) {
        isValid = false;
        message = 'Unmatched brackets or parentheses';
    }

    switch (language) {
        case 'spl':
            if (!query.toLowerCase().startsWith('search')) {
                isValid = false;
                message = 'SPL query must start with "search"';
            }
            break;
        case 'eql':
            if (!query.toLowerCase().startsWith('sequence')) {
                isValid = false;
                message = 'EQL query must start with "sequence"';
            }
            break;
        case 'kql':
            if (!query.includes('|')) {
                isValid = false;
                message = 'KQL query must contain at least one pipe operator';
            }
            break;
    }

    alert(isValid ? 'Query syntax is valid!' : `Invalid query: ${message}`);
    return isValid;
}
