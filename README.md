# Phishing-Analysis-Email-Security-
# Phishing Analysis & Email Security Project

A comprehensive cybersecurity project demonstrating hands-on phishing analysis, email forensics, and incident response capabilities for SOC analyst roles.

## 📋 Project Overview

This project covers the complete lifecycle of phishing analysis and response, from identifying malicious emails to implementing defensive countermeasures. Through six progressive modules, I developed practical skills in threat detection, digital forensics, and security operations.

## 🎯 Scenarios Covered

### 1. **Phishing Email Identification**
- Analyzed various phishing techniques including spear phishing, credential harvesting, and social engineering tactics
- Identified psychological manipulation methods (urgency, authority, scarcity, curiosity)
- Examined real-world phishing campaigns including Emotet malware distribution

- ![p1](https://github.com/user-attachments/assets/09ac0536-5187-434a-972c-75e4706ad396)


### 2. **Email Header Analysis**
- Investigated suspicious emails from finance intern regarding password expiration notices
- Validated email authentication mechanisms (SPF, DKIM, DMARC)
- Traced email origins through Received headers
- Identified spoofed sender addresses via Reply-To and Return-Path mismatches

- ![p2](https://github.com/user-attachments/assets/f79905f0-1175-43a6-8fb7-eaa824f27178)

- ![p3](https://github.com/user-attachments/assets/56951ebe-5d61-4c9a-95c5-13faa18f15f3)

- ![p3](https://github.com/user-attachments/assets/0ef1e0f9-7079-4366-9fd1-cf403947f3f0)




### 3. **Malicious URL Investigation**
- Examined credential-thieving websites masquerading as Microsoft login pages
- Analyzed URL obfuscation techniques (IDN spoofing, hidden URLs, URL redirectors)
- Conducted threat intelligence gathering without direct site interaction

- ![p4](https://github.com/user-attachments/assets/e8c6a322-f2ee-4afe-8ab4-0860268e2833)

- ![p7](https://github.com/user-attachments/assets/10aa4462-54fb-40b0-81d1-a22ca0f2b2f6)

- ![p8](https://github.com/user-attachments/assets/a8857ab3-ca0b-4fc0-869d-56bfcb11b101)




### 4. **Attachment Analysis**
- **Case 1**: Regional Sales Manager received suspicious Chrome toolbar installation request
  - Extracted and analyzed compressed .zip files containing SalesBookmarks.exe
  - Performed static analysis to identify malicious executable properties
  
- **Case 2**: HR Specialist compromised by infrastructure upgrade document
  - Investigated ransomware delivery via disguised .7z attachment
  - Identified RTLO character spoofing in filename (appearing as PDF but actually .exe)
 
  - ![Pestudio](https://github.com/user-attachments/assets/1220717d-c4b8-4807-9b36-0c4f686afbe2)
 
  - 


### 5. **RTLO Spoofing Detection**
- Uncovered Unicode manipulation techniques to disguise executable files
- Identified homoglyph attacks and zero-width character obfuscation
- Analyzed file signatures and MIME types to reveal true file nature

- ![UNICORD Spoofing](https://github.com/user-attachments/assets/2528bd34-99c5-4fa3-b434-915cb767df39)

- ![p6](https://github.com/user-attachments/assets/05fd93a4-edb2-45ec-afed-8620d0c6a830)

- ![18](https://github.com/user-attachments/assets/09e711c8-6049-4a91-9f03-3964e8b2bfa5)
- 
![17](https://github.com/user-attachments/assets/d33400e0-c526-415c-b36f-5bed960abebe)




### 6. **Incident Response & Remediation**
- Purged malicious emails from multiple user inboxes
- Performed account remediation for compromised credentials
- Implemented email filtering rules to prevent similar attacks
- Conducted post-incident security awareness activities

## 🛠️ Tools & Technologies Used

### Analysis Tools
- **pestudio** - Static malware analysis and PE file inspection
- **VirusTotal** - Multi-engine malware scanning and reputation checking
- **Hybrid Analysis** - Dynamic malware analysis in sandboxed environment
- **urlscan.io** - OSINT tool for safe URL analysis and threat scoring

![Pestudio](https://github.com/user-attachments/assets/cb4ca878-d163-44a8-ada3-2502c48b089e)

![VirusT](https://github.com/user-attachments/assets/8f22ae8e-2e30-49d8-8aca-6ec90ba15823)

![13](https://github.com/user-attachments/assets/b992ecd7-7a10-4f34-af17-5abc8546b0de)



### Investigation Tools
- **AbuseIPDB** - IP reputation lookup and malicious activity tracking
- **Microsoft Outlook** - Email header examination and forensic analysis
- **Command Prompt/Terminal** - Filename verification and RTLO detection
- **Papaparse** - CSV processing for log analysis
![p4](https://github.com/user-attachments/assets/251a3e72-e15e-4f13-b8da-4bd8c99e139c)

![cmd](https://github.com/user-attachments/assets/1c0dea01-5aa6-4ecd-bd19-a6c636d66acb)



### Security Frameworks
- **Exchange Online** - Email filtering and phishing rule creation
- **SPF/DKIM/DMARC** - Email authentication verification
- **MITRE ATT&CK** - Threat mapping (T1566 Phishing, T1598 Phishing for Information)
- **MITRE D3FEND** - Defensive techniques (Email Removal, Credential Eviction)

## 💡 Skills Gained

### Technical Skills
- Email header analysis and SMTP protocol understanding
- Static and dynamic malware analysis techniques
- File signature and hash-based threat identification
- Unicode spoofing and obfuscation detection
- OSINT gathering and threat intelligence correlation
- Log analysis and forensic investigation

### SOC Analyst Competencies
- Phishing triage and severity assessment
- Incident response and containment procedures
- Account compromise remediation
- Security rule creation and tuning
- Cross-referencing multiple data sources for validation
- Documentation and reporting of security incidents

### Defensive Operations
- Email filtering rule implementation
- Proactive threat hunting methodologies
- User awareness and security training guidance
- False positive reduction strategies
- Post-incident recovery procedures

## 🔍 Key Takeaways

- **Multi-layered Analysis**: Never rely solely on file appearance or reputation; use multiple tools and techniques for verification
- **Header Intelligence**: Email headers contain critical forensic data for tracing attack origins and validating authenticity
- **Behavioral Indicators**: Recognizing social engineering tactics is as important as technical detection
- **Rapid Response**: Early identification and swift containment minimize organizational impact
- **Defense in Depth**: Combining user education, technical controls, and monitoring creates robust protection

## 🚀 SOC Readiness

This project demonstrates readiness for Security Operations Center roles through:

- Hands-on experience with industry-standard security tools
- Understanding of attack vectors and threat actor methodologies
- Practical incident response and remediation capabilities
- Application of security frameworks (MITRE ATT&CK, D3FEND)
- Critical thinking in ambiguous security scenarios
- Clear documentation and communication of findings

## 📊 Coverage Statistics

- **Modules Completed**: 6
- **Total Learning Time**: ~2 hours 35 minutes
- **Scenarios Analyzed**: 5+ real-world cases
- **Tools Mastered**: 8+ security platforms
- **Techniques Learned**: 15+ analysis methods

---

**Note**: All scenarios are based on training exercises in controlled environments. No real organizations or individuals were compromised during this project.
