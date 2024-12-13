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
            lt: '<',
            gte: '>=',
            lte: '<=',
            notEquals: '!=',
            notIn: 'NOT IN',
            startsWith: 'LIKE',
            endsWith: 'LIKE'
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
            lt: '<',
            gte: '>=',
            lte: '<=',
            notEquals: '!=',
            notIn: ' not in ',
            startsWith: ':*',
            endsWith: ':*'
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
            gte: '>=',
            lte: '<=',
            notEquals: '!=',
            notIn: '!in',
            startsWith: 'startswith',
            endsWith: 'endswith'
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
    },
    'ransomware-activity': {
        title: 'Ransomware Activity',
        description: 'Detect behaviors commonly associated with ransomware operations',
        parameters: [
            { field: 'ProcessName', operator: 'contains', value: 'vssadmin.exe' },
            { field: 'CommandLine', operator: 'contains', value: 'delete shadows' },
            { field: 'EventID', operator: 'equals', value: '4688' }
        ]
    },
    'unusual-process-execution': {
        title: 'Unusual Process Execution',
        description: 'Identify processes executed from uncommon locations',
        parameters: [
            { field: 'ParentProcessName', operator: 'notEquals', value: 'explorer.exe' },
            { field: 'ProcessPath', operator: 'regex', value: 'C:\\\\Users\\\\.*\\\\AppData\\\\.*' },
            { field: 'EventID', operator: 'equals', value: '4688' }
        ]
    },
    'dns-tunneling': {
        title: 'DNS Tunneling',
        description: 'Detect potential DNS tunneling activity',
        parameters: [
            { field: 'QueryName', operator: 'regex', value: '.*\\.[a-z]{4,}$' },
            { field: 'QueryLength', operator: 'gt', value: '50' },
            { field: 'EventID', operator: 'equals', value: '22' }
        ]
    },
    'malicious-powershell': {
        title: 'Malicious PowerShell Execution',
        description: 'Detect suspicious PowerShell activity',
        parameters: [
            { field: 'ProcessName', operator: 'contains', value: 'powershell.exe' },
            { field: 'CommandLine', operator: 'regex', value: '.*(invoke-mimikatz|downloadstring).*' },
            { field: 'EventID', operator: 'equals', value: '4104' }
        ]
    },
    'unauthorized-access': {
        title: 'Unauthorized File Access',
        description: 'Detect access to sensitive files or directories',
        parameters: [
            { field: 'ObjectName', operator: 'regex', value: '.*\\\\(finance|HR|confidential).*' },
            { field: 'AccessMask', operator: 'in', value: '[0x2, 0x4, 0x20]' },
            { field: 'EventID', operator: 'equals', value: '4663' }
        ]
    },
    'phishing-detection': {
        title: 'Phishing Email Detection',
        description: 'Identify potential phishing email events',
        parameters: [
            { field: 'Sender', operator: 'contains', value: '.*@example.com' },
            { field: 'AttachmentType', operator: 'in', value: '[exe, vbs, js]' },
            { field: 'EventID', operator: 'equals', value: '1000' }
        ]
    }
};
