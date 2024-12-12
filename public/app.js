// Add sanitization utilities at the top of the file
function sanitizeInput(input) {
    if (!input) return '';
    
    // Convert to string if not already
    input = input.toString();
    
    // Remove any HTML tags
    input = input.replace(/<[^>]*>/g, '');
    
    // Encode special characters
    input = input
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#x27;')
        .replace(/\//g, '&#x2F;');
    
    // Remove potentially dangerous characters
    input = input.replace(/[;\\\${}`]/g, '');
    
    return input.trim();
}

function sanitizeQueryValue(value) {
    if (!value) return '';
    
    // Convert to string if not already
    value = value.toString();
    
    // Remove dangerous characters while preserving query syntax
    value = value.replace(/[;\\\${}`]/g, '');
    
    // Preserve array syntax but sanitize content
    if (value.startsWith('[') && value.endsWith(']')) {
        const arrayContent = value.slice(1, -1);
        const sanitizedItems = arrayContent.split(',')
            .map(item => sanitizeInput(item.trim()))
            .filter(Boolean);
        return `[${sanitizedItems.join(', ')}]`;
    }
    
    return value.trim();
}

const queryLanguages = {
    spl: {
        template: 'search {sources} {conditions} | where {timeRange}',
        sourceJoin: 'OR',
        conditionJoin: 'AND',
        operators: {
            equals: '=',
            contains: 'LIKE',
            regex: 'REGEX',
            in: 'IN',
            gt: '>',
            lt: '<'
        },
        logSources: {}
    },
    eql: {
        template: 'sequence by {sources} [{conditions}] {timeRange}',
        sourceJoin: ',',
        conditionJoin: ' and ',
        operators: {
            equals: ':',
            contains: ':*',
            regex: '~',
            in: ' in ',
            gt: '>',
            lt: '<'
        },
        logSources: {}
    },
    kql: {
        template: '{sources} | where {conditions} | {timeRange}',
        sourceJoin: ' or ',
        conditionJoin: ' and ',
        operators: {
            equals: '==',
            contains: 'contains',
            regex: 'matches regex',
            in: 'in',
            gt: '>',
            lt: '<'
        },
        logSources: {}
    }
};

// Query Templates
const queryTemplates = {
    'privilege-escalation': {
        title: 'Privilege Escalation',
        description: 'Detect potential privilege escalation attempts',
        parameters: [
            { field: 'EventID', operator: 'in', value: '[4728, 4732, 4756]' },
            { field: 'GroupName', operator: 'contains', value: 'Admin' }
        ]
    },
    'suspicious-login': {
        title: 'Suspicious Login Activity',
        description: 'Detect potential brute force or suspicious login attempts',
        parameters: [
            { field: 'EventID', operator: 'equals', value: '4625' },
            { field: 'LogonType', operator: 'in', value: '[3, 10]' },
            { field: 'FailureReason', operator: 'contains', value: 'password' }
        ]
    },
    'data-exfil': {
        title: 'Data Exfiltration',
        description: 'Identify potential data exfiltration attempts',
        parameters: [
            { field: 'bytes_out', operator: 'gt', value: '1000000' },
            { field: 'dest_ip', operator: 'regex', value: '^(?!10\\.|192\\.168\\.|172\\.(1[6-9]|2[0-9]|3[01])).*' }
        ]
    },
    'lateral-movement': {
        title: 'Lateral Movement',
        description: 'Detect potential lateral movement activity',
        parameters: [
            { field: 'EventID', operator: 'equals', value: '4624' },
            { field: 'LogonType', operator: 'equals', value: '3' },
            { field: 'AuthenticationPackage', operator: 'equals', value: 'NTLM' }
        ]
    }
};

// Initialize state
let state = {
    parameters: [],
    selectedSources: new Set(),
    customSources: []
};

// Wait for DOM to be fully loaded
document.addEventListener('DOMContentLoaded', () => {
    initializeQueryLanguageConfigs();
    initializeEventListeners();
    updateLogSources();
    updateQueryOutput();
});

function initializeQueryLanguageConfigs() {
    try {
        // Map KQL tables
        queryLanguageData.KQLtables[0].SecurityEventTables.forEach(table => {
            queryLanguages.kql.logSources[table.TableName] = table.Purpose;
        });

        // Map Splunk sources
        queryLanguageData.SplunkLogSources.forEach(source => {
            queryLanguages.spl.logSources[`index=${source.Source.toLowerCase()}`] = source.Purpose;
        });

        // Map Elastic sources
        queryLanguageData.ElasticLogSources.forEach(source => {
            queryLanguages.eql.logSources[source.SourceType.toLowerCase()] = source.Purpose;
        });
    } catch (error) {
        console.error('Error initializing query language data:', error);
    }
}

function initializeEventListeners() {
    // Query Language Change
    const queryLanguageSelect = document.getElementById('queryLanguage');
    queryLanguageSelect.addEventListener('change', (e) => {
        // Sanitize and update the selected value
        const sanitizedValue = sanitizeInput(e.target.value);
        queryLanguageSelect.value = sanitizedValue;
        updateLogSources();
        updateQueryOutput();
    });

    // Time Range Change
    const timeRange = document.getElementById('timeRange');
    const customTimeRange = document.getElementById('customTimeRange');
    timeRange.addEventListener('change', (e) => {
        const sanitizedValue = sanitizeInput(e.target.value);
        timeRange.value = sanitizedValue;
        customTimeRange.style.display = sanitizedValue === 'custom' ? 'block' : 'none';
        updateQueryOutput();
    });

    // Custom Time Range Inputs
    ['startTime', 'endTime'].forEach(id => {
        const element = document.getElementById(id);
        element.addEventListener('change', (e) => {
            element.value = sanitizeInput(e.target.value);
            updateQueryOutput();
        });
    });

    // Template Selection
    document.getElementById('queryTemplate').addEventListener('change', (e) => {
        const sanitizedValue = sanitizeInput(e.target.value);
        if (sanitizedValue) {
            applyTemplate(sanitizedValue);
        }
        updateQueryOutput();
    });

    // Add Parameter Button
    document.getElementById('addParameter').addEventListener('click', () => {
        addParameterRow();
        updateQueryOutput();
    });

    // Add Custom Log Source
    document.getElementById('addCustomLog').addEventListener('click', () => {
        const sourceName = prompt('Enter custom log source name:');
        if (sourceName) {
            const sanitizedSource = sanitizeInput(sourceName);
            if (sanitizedSource) {
                addCustomLogSource(sanitizedSource);
                updateQueryOutput();
            }
        }
    });

    // Copy Query Button
    document.getElementById('copyQuery').addEventListener('click', () => {
        const queryText = document.getElementById('queryOutput').textContent;
        navigator.clipboard.writeText(queryText)
            .then(() => alert('Query copied to clipboard!'))
            .catch(err => console.error('Failed to copy query:', err));
    });

    // Download Query Button
    document.getElementById('downloadQuery').addEventListener('click', () => {
        const queryText = document.getElementById('queryOutput').textContent;
        const blob = new Blob([queryText], { type: 'text/plain' });
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = 'threat-hunting-query.txt';
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
        URL.revokeObjectURL(url);
    });

    // Validate Query Button
    document.getElementById('validateQuery').addEventListener('click', validateQuery);
}

function updateLogSources() {
    const language = document.getElementById('queryLanguage').value;
    const logSourcesContainer = document.querySelector('.log-sources');
    const sources = queryLanguages[language].logSources;
    
    // Clear existing log sources
    logSourcesContainer.innerHTML = '';
    
    // Add language-specific log sources
    Object.entries(sources).forEach(([value, description]) => {
        const sourceLabel = document.createElement('label');
        const sanitizedValue = sanitizeInput(value);
        const sanitizedDescription = sanitizeInput(description);
        sourceLabel.setAttribute('data-tooltip', sanitizedDescription);
        const displayName = sanitizedValue.replace(/^index=/, '').replace(/^source=/, '');
        sourceLabel.innerHTML = `<input type="checkbox" value="${sanitizedValue}"> ${displayName}`;
        sourceLabel.querySelector('input').addEventListener('change', updateQueryOutput);
        logSourcesContainer.appendChild(sourceLabel);
    });

    // Re-add custom sources
    state.customSources.forEach(sourceName => {
        const sanitizedSource = sanitizeInput(sourceName);
        const label = document.createElement('label');
        label.innerHTML = `<input type="checkbox" value="${sanitizedSource}"> ${sanitizedSource}`;
        label.querySelector('input').addEventListener('change', updateQueryOutput);
        logSourcesContainer.appendChild(label);
    });
}

function clearParameters() {
    const parametersContainer = document.querySelector('.parameters');
    parametersContainer.innerHTML = '';
}

function addParameterRow(field = '', operator = 'equals', value = '') {
    const parametersContainer = document.querySelector('.parameters');
    const row = document.createElement('div');
    row.className = 'parameter-row';
    
    const language = document.getElementById('queryLanguage').value;
    const operators = queryLanguages[language].operators;
    
    const sanitizedField = sanitizeInput(field);
    const sanitizedOperator = sanitizeInput(operator);
    const sanitizedValue = sanitizeQueryValue(value);
    
    row.innerHTML = `
        <input type="text" placeholder="Field name (e.g., src_ip)" class="field-name" value="${sanitizedField}">
        <select class="operator">
            ${Object.keys(operators).map(op => 
                `<option value="${sanitizeInput(op)}" ${op === sanitizedOperator ? 'selected' : ''}>${sanitizeInput(op)}</option>`
            ).join('')}
        </select>
        <input type="text" placeholder="Value" class="field-value" value="${sanitizedValue}">
        <button class="remove-parameter">✕</button>
    `;

    row.querySelector('.remove-parameter').addEventListener('click', () => {
        row.remove();
        updateQueryOutput();
    });

    // Add input sanitization to all fields
    row.querySelectorAll('input').forEach(element => {
        element.addEventListener('change', (e) => {
            e.target.value = e.target.classList.contains('field-value') 
                ? sanitizeQueryValue(e.target.value)
                : sanitizeInput(e.target.value);
            updateQueryOutput();
        });
        element.addEventListener('input', (e) => {
            e.target.value = e.target.classList.contains('field-value')
                ? sanitizeQueryValue(e.target.value)
                : sanitizeInput(e.target.value);
            updateQueryOutput();
        });
    });

    row.querySelector('select').addEventListener('change', updateQueryOutput);

    parametersContainer.appendChild(row);
}

function addCustomLogSource(sourceName) {
    const sanitizedSource = sanitizeInput(sourceName);
    const logSources = document.querySelector('.log-sources');
    const label = document.createElement('label');
    label.innerHTML = `
        <input type="checkbox" value="${sanitizedSource}"> ${sanitizedSource}
    `;
    
    label.querySelector('input').addEventListener('change', updateQueryOutput);
    logSources.appendChild(label);
    state.customSources.push(sanitizedSource);
}

function applyTemplate(templateId) {
    const sanitizedId = sanitizeInput(templateId);
    const template = queryTemplates[sanitizedId];
    if (!template) return;

    // Clear existing parameters
    clearParameters();

    // Add template parameters
    template.parameters.forEach(param => {
        addParameterRow(
            sanitizeInput(param.field),
            sanitizeInput(param.operator),
            sanitizeQueryValue(param.value)
        );
    });

    // Update query output
    updateQueryOutput();

    // Update documentation
    updateDocumentation(template);
}

function updateDocumentation(template) {
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
                    `<li><strong>${sanitizeInput(param.field)}</strong> ${sanitizeInput(param.operator)} ${sanitizeQueryValue(param.value)}</li>`
                ).join('')}
            </ul>
        `;
    } else {
        queryExplanation.innerHTML = '';
    }
}

function generateTimeRangeString() {
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

function getSelectedSources() {
    const sources = [];
    document.querySelectorAll('.log-sources input[type="checkbox"]:checked').forEach(checkbox => {
        sources.push(sanitizeInput(checkbox.value));
    });
    return sources;
}

function getParameters() {
    const params = [];
    document.querySelectorAll('.parameter-row').forEach(row => {
        const field = sanitizeInput(row.querySelector('.field-name').value);
        const operator = sanitizeInput(row.querySelector('.operator').value);
        const value = sanitizeQueryValue(row.querySelector('.field-value').value);
        
        if (field && value) {
            params.push({ field, operator, value });
        }
    });
    return params;
}

function updateQueryOutput() {
    const queryOutput = document.getElementById('queryOutput');
    const language = sanitizeInput(document.getElementById('queryLanguage').value);
    const config = queryLanguages[language];
    const sources = getSelectedSources();
    const parameters = getParameters();
    const timeRange = generateTimeRangeString();

    let query = config.template;
    
    // Replace sources placeholder
    const sourcesStr = sources.length > 0 ? sources.join(` ${config.sourceJoin} `) : '*';
    query = query.replace('{sources}', sourcesStr);

    // Replace conditions placeholder
    const conditions = parameters.map(param => {
        const operator = config.operators[param.operator];
        return `${param.field} ${operator} ${param.value}`;
    }).join(` ${config.conditionJoin} `);
    
    query = query.replace('{conditions}', conditions || '*');

    // Replace time range placeholder
    query = query.replace('{timeRange}', timeRange);

    queryOutput.textContent = query;

    // Update optimization suggestions
    updateOptimizationSuggestions(query, parameters);
}

function updateOptimizationSuggestions(query, parameters) {
    const suggestions = document.getElementById('optimizationSuggestions');
    const suggestionsList = [];

    // Check query length
    if (query.length > 1000) {
        suggestionsList.push('Consider breaking down the query into smaller, more focused queries for better performance.');
    }

    // Check for wildcard usage
    if (query.includes('*') && !query.includes('\\*')) {
        suggestionsList.push('Using wildcards might impact performance. Consider using more specific filters when possible.');
    }

    // Check for index usage
    if (parameters.length > 0 && !parameters.some(p => p.field.toLowerCase().includes('time'))) {
        suggestionsList.push('Consider adding a time-based filter to improve query performance.');
    }

    // Display suggestions
    suggestions.innerHTML = suggestionsList.length > 0
        ? `<ul>${suggestionsList.map(s => `<li>${sanitizeInput(s)}</li>`).join('')}</ul>`
        : '<p>No optimization suggestions available.</p>';
}

function validateQuery() {
    const queryOutput = document.getElementById('queryOutput');
    const query = queryOutput.textContent;
    const language = sanitizeInput(document.getElementById('queryLanguage').value);
    
    // Basic syntax validation
    let isValid = true;
    let message = '';

    // Check for empty fields
    if (!query.trim()) {
        isValid = false;
        message = 'Query cannot be empty';
    }

    // Check for balanced brackets and parentheses
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

    // Language-specific validation
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

    // Display validation result
    alert(isValid ? 'Query syntax is valid!' : `Invalid query: ${message}`);
    return isValid;
}
