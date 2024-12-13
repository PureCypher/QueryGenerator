export const queryLanguages = {
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
            lt: '<', 
            as: '~='
        },
        logSources: {}
    }
};

export const queryTemplates = {
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
