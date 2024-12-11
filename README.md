---

# Threat-Hunting Query Generator

## Overview

The **Threat-Hunting Query Generator** is a web application designed to help cybersecurity analysts generate accurate and efficient threat-hunting queries for Splunk (SPL), Elastic Stack (EQL), and Azure Sentinel (KQL). This tool simplifies the process of crafting and optimizing searches by providing customizable templates, log source selection, and integration with Indicators of Compromise (IOCs). It also supports mapping queries to the **MITRE ATT&CK** framework, enabling seamless alignment with known adversary tactics, techniques, and procedures (TTPs).

Built with a focus on security and ease of use, this tool enhances Security Operations Center (SOC) operations by providing analysts with the ability to quickly create and refine queries that are optimized for their specific environments.

## Features

- **Query Generation**: Automatically generate threat-hunting queries in SPL, EQL, and KQL based on customizable templates and user-defined parameters.
- **Customizable Templates**: Create and save templates for frequently used queries, allowing for rapid adaptation to changing threat scenarios.
- **Log Source Selection**: Choose from a variety of log sources (e.g., network, endpoint, cloud) to tailor queries to your data.
- **IOC Integration**: Easily incorporate Indicators of Compromise (IOCs) into queries for more targeted threat detection.
- **MITRE ATT&CK Mapping**: Align queries with the MITRE ATT&CK framework to ensure coverage of adversary TTPs.
- **Multi-Platform Support**: Generate queries for Splunk (SPL), Elastic Stack (EQL), and Azure Sentinel (KQL), ensuring compatibility with your security tools.
- **User-Friendly Interface**: Intuitive design makes it easy for analysts of all skill levels to create and refine queries.
- **Security-First Approach**: Built with the latest security practices to ensure that user data and queries remain confidential.

## Getting Started

### Prerequisites

- A web browser (Chrome, Firefox, or Edge recommended).
- Access to a Splunk, Elastic Stack, or Azure Sentinel instance (for testing and deploying generated queries).

### Installation

This application is hosted online and does not require installation. Simply navigate to the following URL to get started:

```
https://hapticlabs.uk
```

### Usage

1. **Login**: Create an account or log in to access the full set of features.
2. **Select Your Platform**: Choose the platform you are working with (Splunk, Elastic Stack, or Azure Sentinel).
3. **Choose Log Sources**: Select the relevant log sources for your query (e.g., Windows Event Logs, Firewall Logs).
4. **Customize Query Template**: Use the customizable templates or create a new query. Adjust the parameters as needed.
5. **IOC Integration**: Add IOCs to refine your query and target specific indicators.
6. **Map to MITRE ATT&CK**: Select the relevant MITRE ATT&CK techniques to align your query with known adversary behaviors.
7. **Generate and Test Query**: Generate the query and copy it into your security platform for testing.
8. **Save Templates**: Save your query as a template for future use.

### Example Usage

#### Query for Splunk (SPL)

- **Prompt**: Generate a query to detect a possible brute-force attack using failed login attempts.
- **Result**:  
  ```spl
  index=authentication sourcetype=secure_syslog action=failure
  | stats count by src_ip, user
  | where count > 10
  ```

#### Query for Elastic Stack (EQL)

- **Prompt**: Generate a query to detect a suspicious process spawning from a legitimate binary.
- **Result**:  
  ```eql
  process where host.name == "win7" and process.parent.name == "explorer.exe" and process.name in ("cmd.exe", "powershell.exe")
  ```

#### Query for Azure Sentinel (KQL)

- **Prompt**: Generate a query to identify a user accessing a large volume of sensitive data.
- **Result**:  
  ```kql
  SecurityEvent
  | where EventID == 4663
  | where ObjectType == "File"
  | summarize TotalAccessed = count() by User, ObjectName
  | where TotalAccessed > 100
  ```

## MITRE ATT&CK Integration

Each query generated can be mapped to relevant **MITRE ATT&CK** tactics and techniques. This ensures that your threat-hunting efforts are aligned with the latest threat intelligence and adversary behaviors.

To map your query to MITRE ATT&CK:
1. **Select Techniques**: Pick the appropriate ATT&CK techniques that the query is designed to detect.
2. **View TTP Alignment**: The application will display which adversary TTPs the query is most likely to cover.

## Security Considerations

- **Data Privacy**: User data and generated queries are stored securely and are not shared with third parties.
- **Encryption**: All data transmitted between the application and the user is encrypted using HTTPS to ensure confidentiality.
- **Query Integrity**: The application ensures that the queries are accurate and free from errors, and it highlights potential issues or security risks in the generated queries.

## Contributing

Contributions are welcome! To contribute:
1. Fork the repository.
2. Create a new branch for your feature or bug fix.
3. Submit a pull request with a detailed description of the changes.

## License

This project is licensed under the MIT License. See [LICENSE](LICENSE) for more details.

## Contact

For questions or feedback, please contact [@Pur3Cyf3r](https://x.com/Pur3Cyf3r)

## Acknowledgments

- [Splunk Documentation](https://docs.splunk.com/)
- [Elastic Stack Documentation](https://www.elastic.co/guide/index.html)
- [Azure Sentinel Documentation](https://learn.microsoft.com/en-us/azure/sentinel/)
- [goproslowyo](https://x.com/GoProSlowYo)  or [goproslowyo](https://github.com/goproslowyo) for getting me to do this. 
