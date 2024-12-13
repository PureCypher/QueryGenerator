export function sanitizeInput(input) {
    if (!input) return '';
    
    input = input.toString();
    input = input.replace(/<[^>]*>/g, '');
    input = input
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/'/g, '&#x27;')
        .replace(/\//g, '&#x2F;');
    
    input = input.replace(/[;\\\${}`]/g, '');
    
    return input.trim();
}

export function sanitizeQueryValue(value) {
    if (!value) return '';
    
    value = value.toString();
    value = value.replace(/[;\\\${}`]/g, '');
    
    if (value.startsWith('[') && value.endsWith(']')) {
        const arrayContent = value.slice(1, -1);
        const sanitizedItems = arrayContent.split(',')
            .map(item => sanitizeInput(item.trim()))
            .filter(Boolean);
        return `[${sanitizedItems.join(', ')}]`;
    }
    
    value = value.trim();
    if (!value.startsWith('"')) {
        value = '"' + value;
    }
    if (!value.endsWith('"')) {
        value = value + '"';
    }
    
    return value;
}
