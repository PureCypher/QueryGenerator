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

export function updateLogSources() {
    const language = document.getElementById('queryLanguage').value;
    const logSourcesContainer = document.querySelector('.log-sources');
    const sources = queryLanguages[language].logSources;
    
    logSourcesContainer.innerHTML = '';
    state.clearSelectedSources();
    
    Object.entries(sources).forEach(([value, description], index) => {
        const sourceLabel = document.createElement('label');
        const sanitizedValue = sanitizeInput(value);
        const sanitizedDescription = sanitizeInput(description);
        sourceLabel.setAttribute('data-tooltip', sanitizedDescription);
        const displayName = sanitizedValue.replace(/^index=/, '').replace(/^source=/, '');
        
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
        });
        
        sourceLabel.appendChild(checkbox);
        sourceLabel.appendChild(document.createTextNode(` ${displayName}`));
        logSourcesContainer.appendChild(sourceLabel);
    });

    state.getCustomSources().forEach(sourceName => {
        const sanitizedSource = sanitizeInput(sourceName);
        const label = document.createElement('label');
        label.innerHTML = `<input type="checkbox" value="${sanitizedSource}"> ${sanitizedSource}`;
        label.querySelector('input').addEventListener('change', updateQueryOutput);
        logSourcesContainer.appendChild(label);
    });
}

export function addParameterRow(field = '', operator = 'equals', value = '') {
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

export function addCustomLogSource(sourceName) {
    const sanitizedSource = sanitizeInput(sourceName);
    const logSources = document.querySelector('.log-sources');
    const label = document.createElement('label');
    label.innerHTML = `
        <input type="checkbox" value="${sanitizedSource}"> ${sanitizedSource}
    `;
    
    label.querySelector('input').addEventListener('change', updateQueryOutput);
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
