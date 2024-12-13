import { sanitizeInput, sanitizeQueryValue } from '../utils/sanitization.js';
import { queryLanguages, queryTemplates } from '../config/queryConfig.js';
import { state } from '../state/appState.js';
import { updateQueryOutput, validateQuery } from '../query/queryGenerator.js';
import { updateDocumentation } from '../documentation/docHandler.js';

export function initializeEventListeners() {
    initQueryLanguageListener();
    initTimeRangeListener();
    initTemplateListener();
    initParameterListener();
    initCustomLogListener();
    initQueryActionListeners();
}

function initQueryLanguageListener() {
    const queryLanguageSelect = document.getElementById('queryLanguage');
    queryLanguageSelect.addEventListener('change', (e) => {
        const sanitizedValue = sanitizeInput(e.target.value);
        queryLanguageSelect.value = sanitizedValue;
        state.clearSelectedSources();
        updateLogSources();
        updateQueryOutput();
    });
}

async function getFieldsForLogSources() {
    const language = document.getElementById('queryLanguage').value;
    const selectedSources = state.getSelectedSources();
    let fields = new Set();

    const data = await fetch('/queryLangs.json').then(response => response.json());

    if (language === 'kql') {
        selectedSources.forEach(source => {
            // For KQL, the source is the table name
            const table = data.KQLtables.find(t => t.TableName === source);
            if (table) {
                table.Fields.forEach(field => fields.add(field));
            }
        });
    } else if (language === 'spl') {
        selectedSources.forEach(source => {
            // For Splunk, find matching source type
            const logSource = data.SplunkLogSources.find(s => s.SourceType === source);
            if (logSource) {
                logSource.Fields.forEach(field => fields.add(field));
            }
        });
    } else if (language === 'eql') {
        selectedSources.forEach(source => {
            // For Elastic, find matching source type
            const logSource = data.ElasticLogSources.find(s => s.SourceType === source);
            if (logSource) {
                logSource.Fields.forEach(field => fields.add(field));
            }
        });
    }

    return Array.from(fields);
}

function initTimeRangeListener() {
    const timeRange = document.getElementById('timeRange');
    const customTimeRange = document.getElementById('customTimeRange');
    timeRange.addEventListener('change', (e) => {
        const sanitizedValue = sanitizeInput(e.target.value);
        timeRange.value = sanitizedValue;
        customTimeRange.style.display = sanitizedValue === 'custom' ? 'block' : 'none';
        updateQueryOutput();
    });

    ['startTime', 'endTime'].forEach(id => {
        const element = document.getElementById(id);
        element.addEventListener('change', (e) => {
            element.value = sanitizeInput(e.target.value);
            updateQueryOutput();
        });
    });
}

function initTemplateListener() {
    document.getElementById('queryTemplate').addEventListener('change', (e) => {
        const sanitizedValue = sanitizeInput(e.target.value);
        if (sanitizedValue) {
            applyTemplate(sanitizedValue);
        }
        updateQueryOutput();
    });
}

function initParameterListener() {
    document.getElementById('addParameter').addEventListener('click', () => {
        addParameterRow();
        updateQueryOutput();
    });
}

function initCustomLogListener() {
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
}

function initQueryActionListeners() {
    document.getElementById('copyQuery').addEventListener('click', () => {
        const queryText = document.getElementById('queryOutput').textContent;
        navigator.clipboard.writeText(queryText)
            .then(() => alert('Query copied to clipboard!'))
            .catch(err => console.error('Failed to copy query:', err));
    });

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

    document.getElementById('validateQuery').addEventListener('click', validateQuery);
}

export async function updateLogSources() {
    const language = document.getElementById('queryLanguage').value;
    const logSourcesContainer = document.querySelector('.log-sources');
    logSourcesContainer.innerHTML = '';
    state.clearSelectedSources();
    
    const data = await fetch('/queryLangs.json').then(response => response.json());
    let sources = [];

    if (language === 'kql') {
        sources = data.KQLtables.map(table => ({
            value: table.TableName,
            description: table.Purpose
        }));
    } else if (language === 'spl') {
        sources = data.SplunkLogSources.map(source => ({
            value: source.SourceType,
            description: source.Purpose
        }));
    } else if (language === 'eql') {
        sources = data.ElasticLogSources.map(source => ({
            value: source.SourceType,
            description: source.Purpose
        }));
    }
    
    sources.forEach(({value, description}, index) => {
        const sourceLabel = document.createElement('label');
        const sanitizedValue = sanitizeInput(value);
        const sanitizedDescription = sanitizeInput(description);
        sourceLabel.setAttribute('data-tooltip', sanitizedDescription);
        
        const checkbox = document.createElement('input');
        checkbox.type = 'checkbox';
        checkbox.value = sanitizedValue;
        
        if (index === 0) {
            checkbox.checked = true;
            state.addSelectedSource(sanitizedValue);
        }
        
        checkbox.addEventListener('change', (e) => {
            if (e.target.checked) {
                state.addSelectedSource(sanitizedValue);
            } else {
                state.removeSelectedSource(sanitizedValue);
            }
            updateQueryOutput();
            updateFieldDropdowns();
        });
        
        sourceLabel.appendChild(checkbox);
        sourceLabel.appendChild(document.createTextNode(` ${sanitizedValue}`));
        logSourcesContainer.appendChild(sourceLabel);
    });

    updateFieldDropdowns();
}

async function updateFieldDropdowns() {
    const fields = await getFieldsForLogSources();
    document.querySelectorAll('.field-name').forEach(select => {
        const currentValue = select.value;
        select.innerHTML = `
            <option value="">Select a field...</option>
            <option value="custom">Enter custom field...</option>
            ${fields.map(field => `<option value="${sanitizeInput(field)}">${sanitizeInput(field)}</option>`).join('')}
        `;
        if (currentValue) {
            if (fields.includes(currentValue)) {
                select.value = currentValue;
            } else if (currentValue !== 'custom') {
                // If the current value isn't in the fields list and isn't 'custom',
                // add it as a custom option
                const option = document.createElement('option');
                option.value = currentValue;
                option.textContent = `${currentValue} (custom)`;
                select.appendChild(option);
                select.value = currentValue;
            }
        }
    });
}

export async function addParameterRow(field = '', operator = 'equals', value = '') {
    const parametersContainer = document.querySelector('.parameters');
    const row = document.createElement('div');
    row.className = 'parameter-row';
    
    const language = document.getElementById('queryLanguage').value;
    const operators = queryLanguages[language].operators;
    
    const sanitizedField = sanitizeInput(field);
    const sanitizedOperator = sanitizeInput(operator);
    const sanitizedValue = sanitizeInput(value);
    
    // Create field select dropdown
    const fieldSelect = document.createElement('select');
    fieldSelect.className = 'field-name';
    
    // Get fields from selected log sources
    const fields = await getFieldsForLogSources();
    
    fieldSelect.innerHTML = `
        <option value="">Select a field...</option>
        <option value="custom">Enter custom field...</option>
        ${fields.map(field => `<option value="${sanitizeInput(field)}">${sanitizeInput(field)}</option>`).join('')}
    `;

    if (sanitizedField) {
        if (fields.includes(sanitizedField)) {
            fieldSelect.value = sanitizedField;
        } else {
            const option = document.createElement('option');
            option.value = sanitizedField;
            option.textContent = `${sanitizedField} (custom)`;
            fieldSelect.appendChild(option);
            fieldSelect.value = sanitizedField;
        }
    }

    // Handle custom field input
    fieldSelect.addEventListener('change', (e) => {
        if (e.target.value === 'custom') {
            const customField = prompt('Enter custom field name:');
            if (customField) {
                const sanitizedCustomField = sanitizeInput(customField);
                const option = document.createElement('option');
                option.value = sanitizedCustomField;
                option.textContent = `${sanitizedCustomField} (custom)`;
                fieldSelect.appendChild(option);
                fieldSelect.value = sanitizedCustomField;
            } else {
                fieldSelect.value = '';
            }
        }
        updateQueryOutput();
    });

    row.appendChild(fieldSelect);
    
    const operatorSelect = document.createElement('select');
    operatorSelect.className = 'operator';
    operatorSelect.innerHTML = Object.keys(operators).map(op => 
        `<option value="${sanitizeInput(op)}" ${op === sanitizedOperator ? 'selected' : ''}>${sanitizeInput(op)}</option>`
    ).join('');
    row.appendChild(operatorSelect);

    const valueInput = document.createElement('input');
    valueInput.type = 'text';
    valueInput.placeholder = 'Value';
    valueInput.className = 'field-value';
    valueInput.value = sanitizedValue;
    row.appendChild(valueInput);

    const removeButton = document.createElement('button');
    removeButton.className = 'remove-parameter';
    removeButton.textContent = '✕';
    row.appendChild(removeButton);

    removeButton.addEventListener('click', () => {
        row.remove();
        updateQueryOutput();
    });

    operatorSelect.addEventListener('change', updateQueryOutput);
    
    // Only apply quotes when input is complete (change event)
    valueInput.addEventListener('change', (e) => {
        e.target.value = sanitizeQueryValue(e.target.value);
        updateQueryOutput();
    });

    parametersContainer.appendChild(row);
}

export function addCustomLogSource(sourceName) {
    const sanitizedSource = sanitizeInput(sourceName);
    const logSources = document.querySelector('.log-sources');
    const label = document.createElement('label');
    label.innerHTML = `
        <input type="checkbox" value="${sanitizedSource}"> ${sanitizedSource}
    `;
    
    label.querySelector('input').addEventListener('change', () => {
        updateQueryOutput();
        updateFieldDropdowns();
    });
    logSources.appendChild(label);
    state.addCustomSource(sanitizedSource);
}

export function applyTemplate(templateId) {
    const sanitizedId = sanitizeInput(templateId);
    const template = queryTemplates[sanitizedId];
    if (!template) return;

    clearParameters();
    template.parameters.forEach(param => {
        addParameterRow(
            sanitizeInput(param.field),
            sanitizeInput(param.operator),
            sanitizeQueryValue(param.value)
        );
    });

    updateQueryOutput();
    updateDocumentation(template);
}

export function clearParameters() {
    const parametersContainer = document.querySelector('.parameters');
    parametersContainer.innerHTML = '';
}
