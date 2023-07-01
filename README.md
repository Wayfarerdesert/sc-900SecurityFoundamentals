# Azure Security Fundamentals

## ☁️`Security Methodologies`

* * *

## Zero Trust Model (Methodologies)

### Microsoft's Zero trust Model

- **3 Principles**
    
    1.  Verify Explicity
        Always authenticate and authorize based on all available data points.
    2.  Least Privileged Access / Principle of Least Privilege (PoLP)
        Limit user acces with ***Just-In-Time*** and ***Just-Enough-Access*** (JIT/JEA), risk-based adaptative policies, and data protection.
    3.  Assume Breach
        Minimize blast radius and segment acces. Verify and-to-and encryption and use analytics to get visibility, drive threat detection, and improve defense.
- **6 Pillars**
    
    1.  Identities
        Verify and secure each identity with strong authentication across your entire digital estate.
        
        - Identity Access Management (IAM)
        - Azure Active Directory
        - Single Sing On
        - Multi-Factor Authentication
        - Passwordless Authentication
        - Risk-based policies
        - Identity Secure Score
    2.  Endpoints aka Devices
        Gain visivility into devices accesing the network. Ensure compliance and health status before granting acces.
        
        - Register devices to your IpD (Azure AD device management)
        - Microsoft Endpoint Manager
        - Microsoft Defender for Endpoint
        - Data Loss Prevention (DLP) Policies
    3.  Apps
        Discover shadow IT, ensure appropiate in-app permissions, gate acces based on real-time analytics, monitor and control user action.
        
        - Policy-based acces control
        - Microsoft Cloud App Security (MCAS)
        - Cloud Discovery
    4.  Data
        Move from perimeter-base data protection to data-driven protection. Use intelligence to classify label data. Encrypt and restrict acces based on organizational policies
        
        - Sensitivity Labels
        - Microsoft Informaiton Protection
        - Data Classification
        - Azure Information Proteccion (AIP) scanner
        - decision-based policies
        - Data Loss Prevention (DLP) Policies
    5.  Infrastructure
        Use telemetry to detect attaks and anomalies, automatically block and flag risk behavior, and employ least privilege acces principles.
        
        - Azure Security Center
        - Azure AD Managed Identities
        - User and resource segmentation
        - VNeTs
        - Peering rules
        - Privileged Identity Management
        - Network Security Groups (NSG)
        - Aplication Security Groups (ASG)
        - Azure Firewall
        - Microsoft Defender for Endpoint
        - Microsoft Defender for Identity
        - Azure Sentinel
    6.  Network
        Ensure devices and users aren't trusted just because they're on an internal network. Encrypt all internal communications, limit acces by policy, and employ microsegmentation and real-time trheat detection
        
        - Network Segmentation
        - Azure Ddos Protection Service
        - Azure Firewall
        - Azure Web Application Firewall (WAF)
        - Azure VPN
        - Azure AD Proxy
        - Azure Bastion
        - SSL/TLS

### Zero-Trust Assessment Tool

A free tool to acces yout organization degree of adoption towards a Zero-Trust model and suggest to improve your current security implementations.

* * *

### Shared Responsability Model

Describes what the customer and Azure is responsible for related to cloud resources.

Regardless of the type of deployment, the following responsibilities are alqays by user:

- Data
- Endpoints
- Account
- Acces management

* * *

### Defense in Depth

The 7 Layers of Security

1.  Data
    Acces to business and customer data, and encrytion to protect data.
2.  Application
    apps are secure and free of security vulnerabilities.
3.  Compute (VM)
    Access to virtual machines (ports, on-premise, cloud)
4.  Network
    Limit communication between resources using segmentation and access control
5.  Perimeter
    Distributed denial of service (DDoS) protection to filter large-scale attacks before they can cause a denial of service for users.
6.  Identity and access (Policies & Access)
    controlling access to infrastructure and change control.
7.  Physical (Physical Security)
    limiting acces to a datacenter to only authorized personnel.

* * *

### CIA Triad

#### Confidentiality, Integrity, Availability

is a model describing the foundation to security principles and their trade-off relationship.

1.  Confidentiality is a component of privacy that implements to protect our data from unauthorized viewers. In practice this can be using cryptographic keys to encrypt our data, and using keys to encrypt our keys (envelopment encryption).
2.  Integritymantaining and assuring the accuracy and completeness of data over its entire lifecycle. In Practice utilizing ACID compliant databases for valid transactions. Utilizing tamper-evident or tamper proof Hardware security modules. (HSM)
3.  Availability, information need to be made available when needed. In Practice: High Availability, Mitigating DDoS, Decryption acces.

* * *

* * *

## ☁️`Security Conceps`

* * *

### Common Threats

a threat is a potential negative action or event facilitated by a vulneravility that results in an unwanted impact to a computer system or applicatoin

1.  Dictionary Attack: brute forcing into a target accounts by enumerating over a large number of known passwords.
2.  Disruptive atacks: attempts to disrupt a computer system or network for various reasons: DDoS, coin miners, rootkits, trojans, worms, etc.
3.  Ransomware: malicious software(malware) that when installed holds data, workstation or a network hostage until the ransom has been paid.
4.  Data Breach: malicious actor gains unauthorized acces to a system in order to extract private data.

* * *

### Vulnerabilities

a hole or weakness in the application, wich can be design flaw or an implementation bug, that allows an attaker to cause harm to the stakeholders of an application

* * *

### Encryption

the practice and study of techniques for secure communication in the presence of third parties called adversaries.
Encryption is the process of encoding(scrabbling) information using a key and a cypher to store sensitive data in an unintelligible format as a means of protection. An ancryption takes in plaintext and produces ciphertext.

* * *

### Cyphers

An algorithm that performs encryption o decryption. is synonymous with 'code'.
Ciphertext is the result of encryption performed on plaintext via an algorithm.

* * *

### Cryptographyc Keys

is a variable used in conjunction with an encryption algorithm in order to encrypt or decrypt data

1.  **Symmetric encription**: the same key is used for encoding and decoding. eg. Advanced Encryption standard (AES)
2.  **Asymmetric Encryption**: one used to encode and one to decode. eg: Rivest-Shamir_Adleman(RSA)

* * *

### Hashing and Salting

A function that accepts arbitrary size value and maps it to a fixed-size data structur. Hashing can reduce the size of the store value.
Is a **one-way Process** and is **deterministic**. Always return the same input.

1.  Hashing passwords are used to store passwords in database so that a password does not reside in a plaintext format.
    To autenticate a user, when a user inputs their password, it is hashed, and the hash is compared to the stored hashed. If match then the user has successful logged in.
2.  Salting Passwords: is a random string known to the attaker that the hash function accepts to mitigate the deterministic nature of hashing functions.

* * *

### Digital signature

is a mathematical scheme for verifying the authenticity of digital massages or documents. It give us **tamper-evidence**.

1.  did someone mess the data?
2.  is this data not from the expected sender?

There a three algorithms to digital signatures:

1.  Key generation (public and private)
2.  Signing: generating a digital signature with a private key and inputted message.
3.  Signing verification: verify the authenticity of the message with a public key.

* * *

### In-Transit vs At-Rest Encryption

- Encryption In-Transit: data is secured when moving between locations. Algorithms: TLS, SSL
- Encryption At-Rest: data is secured when residing on storage or within a database. Algorithms: AES, RSA

Transport Layer Security(TLS): protocol for data integrity between two or more communicating computer application.
Secure Sockets Layers(SSL): protocol for data integrity between two or more communicating computer application.

* * *

### MFA (Multi-Factor Authentication)

user have to use a second device to authentica loggin.

* * *

### Security Information and Event Management (SIEM)

- Log Management: focus on simple collection and storage of log messages and **audit trails**.
    
    - Security information management (SIM): Long-term storage as well as analysis and reporting of log data.
- Event Logs: systems and apps generate events which are kept in **event logs**. list of activities occurred.
    
    - Security event management (SEM): real-time monitoring, correlation of events, notifications and console views.
        **SIEM** combines SIM and SEM to provide real-time analysis of security alerts generated by network hardware and applications.

* * *

### SOAR - Security Orchestration Automated Response

collects data about security threats and respond to security events without human assistance. The SOAR system then triggers action-driven automated workflows and processes to run security tasks that mitigate the issue.

1.  Secutity Orchestration: connects vatious internal or external security tools via built-in custom integrations.
2.  Security Automation: analizes the injected data to create **Playbooks** (respetable, automated processes to replace manual processes).

* * *

### XDR - Extended Detection Response

is cross-layered detection and response security system. XDR uses a holistic approach to detect and respond to threats that would normally evade detection in a single-vector soltion by collaborating multiple data sources into a multi-vector solution.

* * *

### EDR - Endpoint Detection and Response

Combines real-time continuous monitoring and collection of endpoint data with rules-based automated response and analysis capabilities.

**EDPs are designed to detect APTs**
APT - Advanced Persist Threat: will breach security perimeter and take up residence within a network to steal as much data as it can over a long period of time. APT are threat actors that engineer malware engineered for a particular target. APTs are slow **acting and stealthy**.

* * *

### CASB - Cloud access security brokers

sits between cloud services users and clous applications, and monitors all activity and enforces security policies.

1.  Control and monitoring (Visibility)
2.  Compliance Management
3.  Data Security
4.  Threat Protection

* * *

### Security Posture

- **Malicious Actors** aka Threat Actor, Attacker
- **Inventory** : up to date list of assets (software and hardware), Perimeter assets (public facing), Core assets (private-facing).
- **Attack Vectors** : the method that a malicious actor uses to breach or infiltrate your network.
- **Attack Surface** : the sum of the attack vectors.
- **Security Control** : controls are safeguards or countermeasures to avoid, detect, counteract, or minimize security risks.
- **Security Posture** : A formula to determine the overall effectiveness of a companies security overall defense.

* * *

### CSPM - Cloud Security Posture Management

Identify and remediate risks through security assessments and automated compliance monitoring.
Assesses your system and automatically alerts security staff in your IT department when a vulnerability is found.

- Security Tools:
    1.  Zero Trust-based access control
    2.  Real-time risk scoring
    3.  Threat and culnerability management (TVM)
    4.  Discover sharing risks
    5.  Technical policy
    6.  Threat modeling systems and architectures

* * *

### JIT and JEP ( just-in-time and just enough privilege)

- **JIT** : giving access to resources only during the time when needed reducing the surface attack based on range of time access.
- **JeP** : giving to only the specific actions (API calls), reducing the surface attack by providing least-permissive permissions.

* * *

### Ingress vs Egress

- Ingress trafic that is entering a network boundary
- Egress trafic that is exiting a network boundary

* * *

### Shadow IT

is a business agility process where departments can purchase and provision their own IT resources without the approval of the organization centralized IT department.

- **Advantages**: allows organizations to innovate and quickly prototype future solutions.
- **Disadvantage**: increase risks with organizational requirements for:
    - security control
    - compatibility with compliance programs
    - loss of data, or unexpected data exposure
    - documentation
    - reliability

* * *

### AIR - Automated Investigation and Remediation

- Investigation : gathering evidence from digital systems to uncover malicious intent or reduction in a security posture.
- Remediation : the action of remedying something to prevent or revert a disaster. the act of changing a resource back to the desired state or a state that does not causes problems.
- **Automated Investigation** a service which uses an inspection algorithm that triggers an alert which in turn creates an incident
- **Automated Remediation** : a service which watches for types of incidents and matches it with a remediation action. eg. shut off the server.

* * *

### Threat Modeling / Threat Analysis

Threat analysis is the practice of mitigating possible threats via threat modeling.
Modelling, is a structured process for identifying attackers and cataloging possible threats.

- Threat modelling methodologies :
    - STRIDE
    - PASTA
    - Trike
    - MAL

* * *

### STRIDE Methodology

categorizes different threats as the following:

- Spoofing : illegally accessing and then using another user's authentication info.
- Tampering : malicious modification of data.
- Repudiation : ilegal operation in a system that lacks the ability to trace the prohibited operation.
- Information disclosure : exposure of information to individuals who are not supposed to have access to it.
- Denial of Service : deny service to valid users.
- Elevation of privilege : unprivileged user gains privileged access.

* * *

### IDS / IPS - Intrusion Detection and Protection system

- IDS monitors a network or system for malicious activity or policy violations
    
- IPS restricts acces to a network or systems mitigate malicious activity or policy violations
    
- How does an IDS detect incidents?
    
    - Signature-Based Detection (simple technique)
    - Anomaly-Based Detection (advanced technique)
    - Stateful Protocol Analysis (profile technique)

* * *

### MITRE Attack Framework

is a non-for-profit organization supporting various US goverment agencies.
MITRE ATT&CK is a globally-accessible knowledge base of adversary tactics and techniques based on real-world observations
is used as a foundation for the development of specific threat models and methodologies.

* * *

* * *

## ☁️`Privacy`

* * *

### Microsoft Privacy Principles

1.  Control
2.  Transparency
3.  Security
4.  Strong legal protection
5.  No content-based targeting
6.  Benefits to you

* * *

### Microsoft Privacy

- **Control your data** :
    - your data belongs to you.
    - your control of your data
    - independent audit reports
    - data processing only with consent
    - Subcontractors data restrictions
- **Control data location** :
    - choises for datacenters
    - choises for data residency
- **Securing your data** :
    - data-at-rest
    - data-in-transit
    - Encryption keys - Azure key vault
- **Defending your data** :
    - responding to your data request
    - law enforcement request
    - our contractual commitments
    - GDPR compliance

* * *

* * *

## ☁️`Identity`

* * *

### Primary Security Perimeter

- Security perimeter : barriers or built fortifications to either keep intruders out or to keep captives contained within the area the boundary surrounds.
- Encryption is the point of entry to cross a security perimeter.

**Access Controls (AC)** is the security mechanism at the point of access that allows or denies access permission to acces a resource is called authorization
Azure AD is the most common tool to protect against tool in an Azure or microsoft workloads.

* * *

### Identity Providers IpD

a system that creates, maintains, and manages identity information for principals and also provides authentication services to applications within a federation or distributes network.
**Federated identity** is a method of linking a user's identiy across multiple separate identity management systems.

* * *

* * *

## ☁️`Azure AD`

* * *

### Introduction to Auzre AD

is Microsoft's cloud-based identity and access management service, which helps your employees sing in and access resources.

- External resources:
    - Microsoft Office 365
    - Azure Portal
    - SaaS apps
- Internal Resources:
    - apps within your internal networking
    - Access to workstations on-premise

AD implement **Single-sign On (SSO)**, can authorize and authenticate to multiples sources.

* * *

### Active Directory vs Azure AD

- **Active Directory** Domain Services introduced in windows 2000 to give organizations the ability to manage multiple on-premises infrastructure components and systems using a single identity per user.
- **Azure AD** takesthis aproach, providing organizations with an **Identity as a Service (IDaaS)** solution for all their apps <u>across cloud and on-premises</u>.

1.  **Active directory**: the on-premise version
2.  **Azure Ad**: the **cloud** verson.

* * *

### App Registrations

allows developers to integrate web-applications to user Azure AD authenticate users and request acces to user resources.

* * *

### External Identities

allow people outside your organization to acces your apps and resources, while letting them sing in using whatever identity they prefer.

1.  **B2B** allows external businesses to authenticate with your app
2.  **B2C** allows customers to authenticate with your app.

* * *

### Service Principle

used by applications or services to acces specific Azure resource.
A service principal is created when a user from that tenant has consented to the application's or API's use.

- The **ApplicationId** represents the global application across all tenants.
- The **ObjectID** is a unique value for an application object.

* * *

### Managed Identity

used to manage the credentials for authenticating a cloud app with an Azure service. You can **authenticate to any service** that supports Azure AD authentication <u>without having credentials in your code.</u>

1.  **System-assigned** . an identity in Azure AD tied to the lifecycle of a service instance. when the resource is deleted so is the system-assigned managed identity.
2.  **Used-Assigned** : an identity assigned to one or more instances of services. The identity is managed separately from the resource. When a resource is deleted the identity remains.

* * *

### Device Management

the management of **physical devices** such as <u>phones, tablets, laptops and desktop</u> computers, that are granted access to company resources such as Printers, Cloud Resources via **device-based Conditional Access**.

1.  **Azure AD Registered**:
    1.  personally owned
    2.  signed in with a personal or local account
2.  **Azure AD Joined**:
    1.  by an organization
    2.  signed in with an Azure AD account
    3.  only in the cloud
3.  **Hybrid Azure AD Joined**:
    1.  by an organization
    2.  signed in with an active Directory Domain Service account belonging to that organization
    3.  exist in the cloud and on-premises

* * *

### MDM & MAM

1.**Mobile Device Management MDM**: control the entire device, can wipe data from it, and also reset it to factory settings.
2.**Mobile Application Management MAM**: publich, push, configure, secure, monitor, and update mobile apps for your users.

* * *

### Windows Hello

Gives Windows 10 users an alternative way to log into their devices and applications using:

- fingerprint
- iris scan
- facial recognition

Windows Hello PIN is backed by a Trusted Platform Module (TPM) chip.

* * *

### Azure AD Connect

is a **hybrid service** to connect your on-premise Active Directory to your Azure Account. Allows for seamless **Single Sign On** from your on-premise workstation to Microsoft Azure.

* * *

### SSPR - Self-Service Password Reset

allows users to change or reset their password, whitout the help from an administrator.

Self-Service password scenarios:

1.  Password change
2.  Password reset
3.  Account unlock

* * *

### Password Protection

is a feature of Azure AD to protect your passwords from identity attacks such as **password spray attacks**.
Spraying is a type of brute force dictionary attack.

* * *

### Identity Management Best Practices

Azure identity management and access control security best practices:

1.  Treat identity as the primary security perimeter
2.  Centralize identity management
3.  Manage connected tenants
4.  Enable single sing-on
5.  Turn on Conditional Access
6.  Plan for routine security improvements
7.  Enable password management
8.  Enforce multi-factor verification for users
9.  Use role-based access control
10. Lower exposure of privileged accounts
11. Control locations where resources are located
12. Use Azure AD for storage authentication

* * *

### Emergency Access Accounts or Break Glass

prevent admins from being accidentally locked out of Azure AD. can mitigate the impact by creating **two or more** emergency access accounts in your organization.
Emergency Access Accounts are:

- highly privileged
- limited to emergency or break glass scenarios
- cloud-only accounts that use the * .onmicrosoft.com domain
- not federated or synchronized from an on-premises environment.

* * *

* * *

## ☁️`Azure AD Authentication`

* * *

### Authentication Methods

Azure Active Directory multy-factor authenticathion methods

1.  SMS
2.  Voice call
3.  Microsoft Authenticator app
4.  OATH Hardware token

* * *

### Microsoft Authenticator

secure sign-ins for all your online accounts using:

1.  multi-factor authentication
2.  Passwordless
3.  password autofill

* * *

### Biometrics

are body measurements and calculations related to human characteristics.
Biometric authentication (or realistic authentication) is used in computer science as a form of identification and access control.

| Physiological characteristics: | Behavioral characteristics: |
| --- | --- |
| 1. Fingerprint | 1. typing rhythm |
| 2. Palm venis | 2. Gait |
| 3. Face recognition |     |
| 4. DNA |     |
| 5. Pal print |     |
| 6. hand geometry |     |
| 7. Iris recognition |     |
| 8. Retina |     |
| 9. Odor/scent |     |

* * *

### FIDO 2.0 and Security Keys

**Fast Identity Online (FIDO) Alliance**
An open industry association whose mission is to develop and promote authentication standars that help reduce the world's over-reliance on passwords.
FIDO Alliance has published three sets of open specifications for simpler, stronger user authentication:

1.  FIDO Universal Second Factor (FIDO U2F)
2.  FIDO Universal Authentication Framework (FIDO UAF)
3.  Client to Authenticator Protocols (CTAP)
4.  CTAP is complementary to the W3C's Web Authentication (WebAuthn) specification; together, they are known as **FIDO2**

* * *

### OATH - Open Authentication

Open Authentication is an open standard that specifies how time-based, one-time password (TOTP) codes are generated.
**Time-based One-time Password (TOTP)** is a computer algorithm that generates a one-time password(OTP) which uses the current time as a source of uniqueness.
OATH TOTP is implemented using either software or hardware to generate the codes.

* * *

### Passwordless Authentication

Passwordless Authentication methods are more convenient because the password is removed and replaced with:

| somthing you have | + something you are | or something you know |
| --- | --- | --- |
| windows 10, phone.. | biometrics | PIN |

* * *

* * *

## ☁️`Azure AD Management`

* * *

### Conditional Access

**Azure AD Conditional Access** provides an extra layer of security before allowing authenticated users to access data or other assets.
Conditional Access is implemented through **Conditional Access Policies**.
analyses:

- Signals: user, location, device, application, real-time-risk
- and Verifies every acces attemp via **Access Control**: Require MFA, Block, Allow

Signals is metadata associated with an identity atttemting to gain acces.

#### Common Decisions

define the acces control that decide what level of acces based on Signal information

- **Block acces**: most restrictive decision
- **Grant Access**: least restrictive decision, still require one or more of the following options:
    - MFA
    - device to be marked as compliant
    - Hybrid Azure AD joined device
    - Approved client app
    - app protection policy (preview)

* * *

### Azure AD Roles

are used to **manage Azure AD resources** in a directory such as:

- creating or edit users
- assign administrative roles to others
- reset user passwords
- manage user licenses
- manage domains

A few important Built-In Azure AD roles:

1.  **Global Administrator**: Full acces to everything
2.  **User Administrator**: Full access to create and manage users
3.  **Billing Administrator**: make purchases, manage subscriptions and support tickets

* * *

### RBAC - Role Base Access Control

represents the identities requesting access to an Azure resource such as:

- **User**
- **Group**
- **Service Principal**: a security identity used by applications or services to access specific Azure resources.
- **Managed identity**: an identity in Azure Active Directory that is aitomatically managed by Azure.

**Scope** is the **set of resources** that access for the Role Assignment applies to.
Scope Access control at the Management, Subscription or Resource Group level.

A **Role Definition** is a collection of permissions. List the operations that can be performed, such as **read, write and delete**. It can be hign-level, like owner, or specific, like VM reader.

* * *

* * *

## ☁️`Azure AD Protection Governance`

* * *

### Identity Governance

**Azure AD** allows to govern identities to balance and organization security vs employee productivity.
Ensure that the risht people have the righ access to the right resources.
**Azure AD and Enterprise Mobility + Security** features allows you to mitigate access risk by protecting, monitoring, and auditing access tocritical assets.

it give organizations the ability to do the following:

1.  Govern the identity lifecycle
2.  Govern access lifecycle
3.  Secure privileged access for administration

* * *

### HCM - Human Capital Management

The practice of managing people as resources within an organization.
HCM is an app that provide **administrative** and **strategic** support around human resources

- Administration:
    - Payroll
    - benefits
    - Employee self-service portal
- Strategic:
    - Workforce planning
    - Competency management
    - Performance management
    - Time and expense management
    - Education and training
    - Recruitment
    - Onboarding
    - Organization visualization

* * *

### Identity Lifecycle

is the **foundation** for identity Governance. The goal is to achive a balance between **productivity and security**.

Azure AD Premium automatically mantains user identities for people represented in **Workday** and **SAP SuccessFactors** in both Active directory and Azure Active Directory.

* * *

### Access Lifecycle

is the process of managing user access throughout their lifecycle in an organization.

- **Azure AD Dynamic Groups** determine group membershio based on user or devices properties.
- **Azure AD acces reviews** enforce reviews on a regular basis to make sure only the right people have continued access.
- **Azure AD entitlement management** enable you to define how users request access across packages of group and team membership, app roles, and SharePoint Online roles.

* * *

### Privilege Acces Lifecycle

is the management of fine-grade permissions over the life-cycle of a user within an organization
**Azure AD Privileged Identity Management (PIM)** provides additional controls to securing access rights for resources, across Azure AD, Azure, and other Microsoft Online Services.

* * *

### Entitlement Management

is an identity governance feature that anables organizations to manage identity and access lifecycle at scale, by automating: **access request workflows, access assignments, reviews, expiration**.
is a feature of Azure AD Premium2. take a bunch of resources, bundled it into an access pakage, then apply it to internal or external users that for a specific range of time.

- **Project** : a logical container for your catalog and access packages
- **Catalog** : resources that are assigned to the project

**Access package** can manage:

- Group membership
- Cloud app access and access rights
- SharePoint online sites
- Organizational and technical roles

* * *

### PIM - Privileged Identity Management

is an Azure AD service enabling you to **manage, control, and monitor access** to important resources in your organization

is a feature of **Azure AD Premium2**

* * *

### Identity Protection

is an Azure AD that's you to **detect, investigate, remediate and export** for future analysis **identity-based risks**.

Identity Protection notices:

- Risky Users
- Risky Sing-Ins
- Risk Detections

* * *

### Detection and Remediation

Identity Protection identifies for the following risks:

- Anonymous IP address
- Atypical travel
- Malware linked IP address
- Unfamiliar sing-in properties
- Leaked Credentials
- Passwords spray
- Azure AD threat intelligence
- New country
- Activity from anonymous IP address
- Suspicious inbox fordwarding

The risks signals can **trigger remediation efforts** such as requiring users: Azure AD MFA, reset password using self-service password reset, or blocking untill an administrator takes action.

* * *

### Investigation

Identity Protection categorizes risk into three tiers: **low, medium, and high**.
Key reports that admin use for investigations in identity Protection:

1.  **Risky Users**:
    - Details about detections
    - History of all risky sing-ins
    - Risk history
2.  **Risky sing-ins**
    - Which sing-ins are classified as at risk
    - real-time and aggregate risk levels with sing-in attempts.
    - Detection types triggered
    - Conditional Access policies applied
    - MFA details
    - Device, app, location info
3.  **Risk Detections**: contains filterable data for p to the past 90 days
    - info about each risk detection including type.
    - Other risk triggered at the same time
    - Sing-in attempt location
    - link out to more detail from MCAS

* * *

* * *

## ☁️`Azure NSG - Network Security Groups`

* * *

### NSG Rules

NSG filter network traffic to and from Azure resources in VNet. and is composed of many Security Rules
Each security rule has the following properties:

- name
- source or destination
- port range
- protocol
- action
- priority

* * *

### Default Security Rules

Azure sets the following default security rules when you create an NSG:

- **inbound rules** to traffic entering the NSG
- **outbound rules** to traffic leaving the NSG

* * *

### Security Rules Logic

has a lot of logic to determine how to apply its rules:

- you may not create two security rules with the same priority and direction
- you can have 5000 NSG per subscription, 1000 NSG rules per NSG
- **Prioritiy**
- **Flow Records**
- **Statefulness**
- **Interruption**

* * *

### NSG Combinations

1.  when there is no NSG assigned to the Subnet or NIC then **all traffic is allowed**
2.  when an NSG is assigned to the NIC and no NSG at the subnet than **rules are predictable based** on allow and deny rules.
3.  an NSG applied to a **subnet applies its rules to all resources in that subnet**

* * *

* * *

## ☁️`Azure Firewall`

* * *

### Azure Firewall

is a managed, **cloud-based network security service** that protects your Azure VNets resources.
It is a fully stateful Firewall as a Service (FWaaS) with:

- built-in high availability
- unrestricted cloud scalability
    Azure Firewall uses a static public IP address for your VNer resources allowing outside firewalls to identify trafic originating from your virtual network. Is integrated with Azure Monitor for logging and analytics.

* * *

* * *

## ☁️`Azure DDoS Protection`

* * *

### Azure Ddos Protection

Distributed Denaial of Service. A malicious attempt to disrupt normal traffic by flooding a website with large amounts of fake traffic.

- **Volumetric attacks**
- **Protocol attacks**
- **Application layer attascks**

1.  DDoS Protection Basic
2.  DDoS Protection Standard

* * *

* * *

## ☁️`Azure Bastion`

* * *

### Azure Bastion

is an **intermediate harden instance** you can use to connect to your target server via SSH or RDP. It will provision a web-based RDP client or SSH Terminal.

Some devices cannot run an RDP Client such as Google Chromebook and so Azure Bastion is one of the only ways to allow yoy to do that.

* * *

* * *

## ☁️`Azure WAF - Web Application Firewall`

* * *

### Azure WAF

is a service that protects wee-apps comunication on the application layer (layer 7) by **analyzing incoming HTTP requests**.
WAFs for cloud providers are generally attached to Load Balancers, API Gateways or CDNs.
can be attached to:

- Azure Application Gateway (an app load balancer)
- Azure Front Door (CDN)
- Azure Content Delivery Network (CDN)
    Azure WAF uses the **Core Rules Set (CRS)** by OWASP to protection against common vulnerabilities.

* * *

* * *

## ☁️`Encryption`

* * *

### Encryption Overview

- **Azure Storage Service Encryption (SSE)**
    - protect data at rest by automatically encrypting before persisting it to:
        - Azure-managed disks
        - Azure Blob Storage
        - Azure Files
        - Azure Queue Storage
    - It is also used to decrypt data on retrieval

* * *

### Azure Disk Encryption

**Azure Managed Disks** supports 2 types of encrtyption:

- Server Side Encryption (SSE)
    provides encryption-at-rest and safeguards yout data to meet your organizational security and compliance commiments. anabled **by default** for all managed disks, snapshots, and images.
    - keys can be managed two ways:
        - Plataform-managed keys: Azure manages your keys
        - Customer-managed keys: you manage your keys
- Azure Disk Encryption (ADE)
    allows you to **encrypt the OS and Data** disks used by an IaaS Virtual Machine
    - ancrypt Windows and Linux IaaS virtual machine disk
    - Uses BitLocker feature on Windows or DM-Crypt on Linux

* * *

### TDE - Transparent Data Encryption

**encrypts data-at-rest** for Microsoft Databases
TDE can be applied to:

- SQL Server
- Azure SQL Database
- Azure Synapse Analytics

* * *

### Key Vault

helps you safeguard **cryptographic keys and other secrets** used by cloud apps and services.

- Secrets Management:
    store an tightly control access to **tokens, passwords, certificates, API keys and other secrets**
- Key Management
    create and control the **encryption keys** used to ecrypt your data
- Certificate Management
    easily provision, manage and deploy public and private **SSL certificates** for use with Azure and internal connected resources
- Harware Security Module - HSM
    secrets and keys can be protected either by software or **FIPS 140-2 Level 2** validated HSMs

* * *

* * *

## ☁️`Azure Security Center`

* * *

### ASB - Azure Security Benchmark

includes a collection of high-impact security recommendations you can use to help secure the services you use in Azure.
It includes **Security Controls** and **Service Baselines**.
is influenced by:

- Cloud Adoption Framework
- Azure Well-Architected Framework
- Microsoft Security Best Practices

1.  **Security Controls** recommendations are generally applicable across your Azure tenant and Azure services. It identifies a list of stakeholders that are typically involved in planning, aproval, or implementation of the benchmark.
2.  **Service Baselines** apply the controls to individual Azure services to provide recommendations on that service's security configuration.

A security baseline is a set of **minimum security controls** defined for:

- low-impact information system
- moderate-impact information system
- high-impact information system

* * *

### Azuire Security Center

is a **unified infrastructure security management system**. It strengthens the security posture of your data centers, and provides advanced threat protection across your hybrid workloads in the cloud.
Continually assesses your resources, subscriptions, and organization for security issues.
are recommendations of actionable security items that will help improve your overall security score.

* * *

* * *

## ☁️`Azure Defender`

* * *

### Azure Defender

provides **advances protection** for your Azure and on-premise workloads. Can be found in the Azure Security Center.
is composed of:

1.  Coverage: lets see the resources typed that are in your subscrition
2.  Security Alerts: describe details of the affected resources, suggested remediation steps
3.  Insights: is a rolling pane of news, suggested reading, and high priority alerts
4.  Advanced Protection: are aditional security features that is driven by analytics

* * *

* * *

## ☁️ `Azure Sentinel`

* * *

### Azure Sentinel

is a scalable, cloud-native:

- **security information event management (SIEM)**
- **security orchestration automated response (SOAR)**

Delivers intelligent security analytics and threat intelligence across the enterprise, providing a single solution for:

- alert detection
- threat visibility
- proactive hunting
- threat response

* * *

### Data Sources

Azure Sentinel comes with a number of commectors for Microsoft solutions:

- Microsoft 365 Defender
- Office 365
- Azure AD
- Microsoft Defender for Identity
- Microsoft Cloud App Security

Use common event formats:

- Syslog
- REST-API
- Windows Event Logs
- Common Event Format (CEF)
- Trusted Automated eXchange of Indicator Information (TAXII)

* * *

### Workbooks

provide a flexible **canvas for data analysis** and the creation of rich visual reports within the Azure portal.
They allow you to tap into multiple data sources from across Azure and combine them into unified interactive experiences.
It tells a **story** about the performance and availability about your applications and services.

* * *

### Sentinel Features

- uses analytics to correlate alerts into **incidents**, that are groups of related alerts that together create an actionable possible-threat that you can investigate and resolve.
- automation and orchestration solution provides a highly-extensible architecture that enable automation as new technologies and threats emerge.
- **investigation tools** help you to understand the scope and find the root cause, of a potential security threat.
- **hunting search-and-query tools**, based on the MITRE framework, wich enable you to proactively hunt for security threats across your organization's data source, before an alert is triggered.

* * *

### Sentinel Pricing

| **Capacity Reservations** | **Pay-As-You-go** |
| --- | --- |
| billed a fixed fee based on the selected tier, enabling a predictable total cost for Azure Sentinel. | billed per gigabyte (GB) for the volume of data ingested for analysis in Azure Sentinel and stored in the Azure Monitor Log Analytics workspace. |

* * *

* * *

## ☁️`M365 Defender`

* * *

### M365

Microsoft 365 (formally Office 365) is a **suite of business software** packaged a as SaaS ofering

* * *

### M365 Defender

is a **unified pre- and post-breach enterprise defense suit** that natively coordinates:

- responses: **detection, prevention, investigation**
- across: **endpoints, identities, email, applications**

to provide integrated protection against sophisticated attacks.

* * *

### Secure Score

is a representation of your organization's **security posture**, and your opportunity to improve it via **Improvement Actions**

* * *

### Defender for Endpoint

are the set of destination IP addresses, DNS domain names, and URLs for Microsoft 365 traffic on the Internet.

endpoints are grouped into four service areas:

1.  Exchange Online
2.  SharePoint Online and OneDrive for Business
3.  Skype for business Online and Microsoft Teams
4.  Microsoft 365 Common and Office Online

Microsoft Defender for Endpoint is an enterpricese endpoint security platform designed to help enterprise networks **prevent, detect, investigate, and respond** to advanced threats.

- Endpoint behavior sensors
- Cloud security analytics
- Threat intelligence

* * *

### Security Reports

is a general security dashboard about **security trends for M365 Identities, devices and Apps**. Information is organized as CARDS on the dashboard:

| **Identities** | **Devices** | **Apps** |
| --- | --- | --- |
| Users at risk | Devices at risk | Risk levels |
| Global admins | Devices Compliance |     |
|     | Devices with active malware |     |
|     | Types of malware on devices |     |
|     | Malware on devices |     |
|     | Devices with malware detection |     |
|     | Users with malware detections |     |

* * *

### Defender for Indentity

is a cloud-based security solution that laverages your on-premises Active Directory signals **to identify, detect, and investigate** advanced threats, compromised identities, and malicious insider actions directed at your organization.
monitors your domain controller by capturing and parsing network traffic and leveraging Windows events derectly from your domain controllers, then analyzes the data for attacks and threats.

* * *

### Defender for Office 365

protects against advanced threats by email messages, links (URLs), and Microsoft Teams, SharePoints Online, OneDrive for Business, and other Office clients

Protection is provided via:

- Reports
- Threat Investigation
- Threat Response
- threat protection policies

There three available subscriptions:

1.  Exchange Online Protection (EOP)
2.  Microsoft Defender for Office 365 Plan 1 (Defender for Office P1)
3.  Microsoft Defender for Office 365 Plan 2 (Defender for Office P2)

* * *

### MCAS - Microsoft Cloud App Security

is a **Cloud Access Security Broker (CASB)** that sits between the user and the cloud service provider to gatekeep acces in real-time to cloud resources.

MCAS is built on -top of the 4 principles of the **Microsoft Cloud App Security Framework**:

1.  Discover and control the use of Shadow IT
2.  Protect your sensitive information anywhere in the cloud
3.  Protect against cyberthreats and anomalies
4.  Assess the compliance of your cloud apps

* * *

* * *

## ☁️ `Microsoft Endpoint Manager`

* * *

### Microsoft Endpoint Manager

Microsoft Intune and Configuration Manager was merged into a single service called **Microsoft Endpoin Manager**.

**Microsoft Intune**: used for managing the security of mobile devices
**Configuration Manager**: used to manage desktops, servers and laptos

Microsoft Intune is a **mobile device and mobile app manager (MDM and MAM)**.

* * *

* * *

## ☁️ `Compliance`

* * *

### Regulatory Compliance

compliance is a rule, such as an specification, policy, standar or law.
RC is when an organization that take effort to comply with relevant **laws, policies, and regulation**.

can vary at the following levels:

- federal
- state
- political and economic union
- international organization

Compliance control are mechanisms that nedd to be in place to detect, prevent, and correct compliance issues.

* * *

### M365 Compliance Center

provides easy access to the data and tools you need to manage to your organization's compliance needs.

roles that have access to:

1.  global administrator
2.  compliance admin
3.  compliance data admin

* * *

### Azure Trust Center

a public-facing website portal providing easy access to **privacy** and **security** and **regulatory compliance** information.
it has audit reports independent for Microsoft's Cloud services for:

- ISO
- SOC
- NIST
- FedRAMP
- GDPR

* * *

### Compliance Manager

At-a-glance summary of the shared responsability model for Microsoft and your Organization.

- Microsoft Trust Center - Compliance Manager (classic)
- M365 Compliance Center - Con¡mpliance Manager

1.  Risk assessment workflow and managemetn tools
2.  Intelligent tracking

Each assessed control will be labeled:

- Preventive, Detective or Corrective
- Mandatory or Discretionary

* * *

### Compliance Programs

- Criminal Justice Information Services (CJIS)
- Cloud Security Alliance (CSA) STAR Certification
- General Data Protection Regulation (GDPR)
- EU Model Clauses
- Health Insurance Portability and Accountability Act (HIPAA)
- International Organization for Standarization (ISO) and the International Electrotechnical Commission (IEC) 27018
- Multi-Tier Cloud Security (MTCS) Singapore
- Service Organization Control (SOC) 1, 2, 3
- National Institute of Standars and Technology (NIST) Cybersecurity Framework (CSF)
- UK Goverment G-Cloud
- Federal Information Processing Standard (FIPS) 140-2

* * *

* * *

## ☁️ `Protection and Governance`

* * *

### MIP - Microsoft Information Protection

is a collection of features within M365 Compliance to help you **discover, Classify and protect** sensitive information wherever it lives or travels.

MIP capabilities:

- Know your data
- Protect your data
- Prevent Data Loss
- Govern your Data
    - GIP

* * *

### Know Protect Prevent

1.  **Know your data**: understand your data landscape and identify important data across your hybrid environment
    1.  Sensitive Information typed
        1.  Built-in sensitive labels
    2.  Trainable classifiers
        1.  Trainable classifiers
    3.  Data classification
        1.  Content explorer
        2.  Activity explorer
2.  **Protect your data**: apply **flexible protection** actions that include encryption, access restrictions, and visual markings
    1.  sensitivity labels
    2.  Azure information protection unified labeling client
    3.  Double Key Encryption
    4.  Offic 365 Message Encryption (OME)
    5.  service encryption with customer key
    6.  sharePoint information Rights Management (IRM)
    7.  rights management connector
    8.  Azure Information Protection unified labeling scanner
    9.  Microsoft Cloud App security
    10. Microsoft Information Protection SDK
3.  **Prevent Data Loss**: prevent accidental oversharing of sensitive information
    1.  data loss prevention (DLP)
    2.  Endpoint data loss prevention
    3.  Microsoft Compliance Extension - Chrome extension
    4.  Microsoft 365 data loss prevention on-premises scanner
    5.  Protect sensitive information in Microsoft Teams chat and channel messages

* * *

### GIP

**Microsoft Informatoin Governance (MIG)** a collection of features to govern your data for compliance or regulatory.

**Information governance**

- reaction policies and retention labels
- import service
- archive third-party data
- inactive mailboxes

**Records management**
a single solution for email and documents that incorporates retention schedules and requirements into a file plan that supports the fll lifecycle of your content with records declaraion, retention and disposition

* * *

### Sensitive Information Types

**are classifications (categories) of data by sensitivity**. Within M365 Compliance Data Classification you get a **breakdown** of the distribution of sensitive into types.
Types identified based on regex or a function.
Sensitive information types are used in:

- Data loss prevention policies
- Sensitivity labels
- Retention labels
- Insider risk management
- Communication compliance
- Auto-labelling policies

* * *

### Trainable Classifiers

A Classifier is a machine learning model that **can take records of data and classify (categorized) by applying a label** from a predetermine list of categories.

M365 Compliance center has two kinds of Trainable Classifiers:

1.  **Pre-Trained Classifiers**: ready to use with five pretrained classifiers. you dont need to provide any data used for training. Meets many general cases.
    1.  Resumes
    2.  Source Code
    3.  Harassment
    4.  Profanity
    5.  Threat
2.  **Custom Trainable Classifiers**: when you have your own kind if documents, specific business documents. You will have to provide training data.

* * *

### Content Explorer

Drill down to find enails (Microsoft Exchange) and documents (OneDrive and sharePoint) that's been labeled based on

- Sensitive info types
- Sensitivity labels
- Retention labels

* * *

### Activity Explorer

Helps discover **which file labels were changed**, and **which files were modified**.
Monitors label activity across Exchange, SharePoint, OneDrive and endpoint devices.

* * *

### Sensitivity Labels

allow you to **apply a label to your documents or emails**, The most common way is via buitl-in dropdown within Office 365 producs.
Makes it easy to apply to do:

- **Content marking** : watermarks, warnings are applied to the heather and footer of a document.
- **Endcryption**: apply encryption and specific which users and groups may decrypt and other fine-tune permissions.

Within M365 Compliance Center under classification you can see the distribution of sensitive labels applied to documents and emails or based on location.

* * *

### Label Policies

In order to use Sensitivity labels they need to be **published** along with a **label policy**. A label Policy determines who can use the labels and other conditions.

- choose the users and groups that can see labels
- apply a default label to all new emails and documents that the specified users and groups create.
- require justifications for label changes
- require users to apply a label (mandatory labeling)
- link users to custom help pages.

* * *

### Retention Labels and Policies

- **retention labels** ensure **data is held for a specific duration** to meet a regulatory compliance or industry best practices.
- **Retention Polices** are used to assign the same retention setting to content at a site level or mailbox level.

* * *

### Records Management

An organization process of managing an organization's information throuhout its life cycle. Record management helps organization meeting regulatory compliance (legal requirements).
**Lifecycle of a record**:

- identifying
- classifying
- storing
- securing
- retrieving
- tracking
- destroying
- preserving

* * *

### DLP

M365 çcompliance Center Data Loss Protection (DLP) policies prevent data loss.
DLP policies allows you to:

- identify, monitor and automatically protect sensitive information in M365
- help users learn how compliance works
- view DLP reports

DLP policies are composed of:

- **Conditions**
    - Matiching content before rule is enforced
- **Actions**
    - What actions to take when the condition is found
- **Locations**
    - Where the policy shoul be applied

* * *

* * *

## ☁️ `Risk Capabilities`

* * *

### Insider Risk Management

minimize internal risks by enabling you to detect, investigate, and act on malicious and inadvertent activities in your organization

Define the types of risk to identify and detect in your organization, including acting on cases and escalating cases to Microsoft Advanced eDiscovery if needed.
Insider Risk Management is looking to detect:

- leaks of sensitive data and data spillage
- confidentiality violations
- intellectual property (IP) theft
- fraud
- insider trading
- regulatory compliance violations

Insider Risk Management uses the following workflow:

1.  Policy: pre-defined templates and policy conditions that define what triggering events and risk indicators are examined in your organization
2.  Alerts: automatically generated by risk indicators that match policy conditions and are displayed in the Alerts dashboard
3.  Triage: reviewers can view alert details for the activities identified by the policy, view user activity associated with the policy match, see the severity of the alert, and review user profile info.
4.  Investigate: provides an all-up view of all active cases, open cases over time, and case statistics for your organization. Cases are created for alerts that require deeper review and investigations of the activity
5.  Action

* * *

### Communication Compliance

helps minimize communication risks by helping you detect, capture, and act on inappropriate mesasges in your organization.
Pre-defined and custom policies allow you to scan internal and external communications for policy matches so they can be examined by designated reviewers.

Communication Compliance can:

- scanning increasing types of communication channels
- the increasing volume of message data
- regulatory enforcement and the risk of fines

Scenarios for Communication Compliance:

- Corporate policies
- Risk management
- Regulatory compliance

Communication Compliance monitor:

1.  **Configure**: identify your compliace requirements and configure applicable communication compliance policies.
2.  **Investigate**: issues detected as matching your communication compliance policies.
3.  **Remediate**: remediate communication compliance issues you've investigated
4.  **Monitor and Report**: Communication Compliance dashboard widgets, export logs and events recorded in the unified audit logs to continually evaluate and improve your compliance posture

* * *

### Information Barriers

are policies that admins can configure to **prevent individuals or groups from communicating with each other**.
Only support **two-way restrictions**.

Use cases:

- Education
- Legal

* * *

### Privilege Access Management

protect your organization from breaches and helps to meet compliance best practices by limiting standing access to sensitive data or access to critical configuration setting.
**Just-in-time acces rules** are implemented for tasks that need elevated permissions and lets an organization operate with Zero standing access.

- create an approver's group
- enable privileged access management
- create an access policy
- submit/approve privileged acces requests

* * *

### Customer Lockbox

**Protects sensitive data when working with Microsoft Support Engineers** by enforcing a request system to view custom private information to resolve a M365 related issue.

Customer Lockbox supports requets to access data for:

- Exchange Online
- SharePoint Online
- OneDrive for Business

* * *

### eDiscovery - Electronic discovery

the process of identifying and delivering electronic information that can be used as evidence in legal cases.

Microsoft 365 provides the following eDiscovery tools:

- **Content search**: running a seach across content.
- **Core eDiscovery**: a workflow to search and export content
- **Advanced eDiscovery**: end-to-end workflow to preserve, collect, review, analyze and export content for internal or external investigation

* * *

### Core eDiscovery Workflow

Core eDiscovery in Microsoft 365 provides a basic eDiscovery tool that organizations can use to search and export content in Microsoft 365 and Office 365.
You can also use Core eDiscovery to place an eDiscovery hold on content locations, such as Exchange mailboxes, SharedPoints sites, OneDrive accounts, and Microsoft Teams.

initial setup:

- Verify and assing appropriate licenses
- Assign eDiscovery permissions
- Create a Core eDiscovery case

Use:

- Create a eDiscovery Hold
- Search for content
- Export and donwload seach results

* * *

### Content Search and Holds

to perform a content search, create a new search, specific the locations and provide keywords and condditions. Leaving keywords blank will return all items with the conditions.

An **sDiscovery Hold** preserves content that might be relevant to a specific eDiscovery case.
you can place a hold in:

- exchange mailboxes
- Onedrive for business
- Microsoft Teams
- Office 365 Groups
- Yammer Groups

Content is preserved until you remove the content location from the hold or until you delete the hold.

* * *

### Advanced eDiscovery Workflow

is end-to-end workflow to preserve, collect, review, analyze and export content that's relevant to your organization's internal and external investigations. It also lets legal teams manage the entire legal hold notification workflow to communicate with custodians involved in a case.

The built in Workflow of advanced sDiscovery described below alings with the Electronic Discovery Reference Model (EDRM), a framework that outlines standars for recovery and discovery of digital data.

* * *

### M365 Audit

audit is the investigation of security events, forensic investigations, internal investigations and compliance obligations. An audit would involve **capturing, recording and retaining** a unified audit log.

M365 has two auditing solutions:

| **Basic Audit** | **Advanced Audit** |
| --- | --- |
| Enabled by default | Includes all the basic Audit features |
| thousands of searchable audit events | Audit log retention policies |
| 90-days audit record retention | Longer retention of audit records |
| Export audit records to a CSV file | High-value, crucial events |
| audit tool in the compliance center | Higher bandwidth to the Office 365 Management Activity API |
| access to audit logs via Office 365 Management Activity API |     |
| Search-UnifiedAuditLog cmdlet |     |

* * *

* * *

## ☁️ `Azure Security Concepts`

* * *

### Resource Locks

As an admin, you may need to **lock a subscription, resource group, or resource** to prevent other users from accidentally deleting or modifying critical resources.

- **ReadOnly**: authorized users can read a resource, but they can't delete or update the resource
- **CanNotDelete**(Delete): authorized users can still read and modify a resource, but they can't delete the resource.

* * *

### Resource Tags

A tag is a **key and Value pair** that you can assing to azure resources.
Tags allow you to organize your resources in the following ways:

- Resource management: specific workloads, environments
- Cost management and optimization: cost tracking, budgets, alerts
- Operations management: business commintments and SLA operations
- Security: classification of data and security impact
- Governance and regulatory compliance

* * *

### Azure Blueprints

anable quick creation of **governed subscriptions**.
Compose artifacts based on common or organization-based patterns into re-usable blueprints.
are a declarative way to orchestrate the deployment of various resource templates and other artifacts such as:

- Role Assigment
- Policy Assigment
- Azure Resource Manager templates (ARM templates)
- Resouce Groups

* * *

### Azure Policy

enforce organizational standards and to assess **compliance** at-scale. Policies do not restrict access, they only observe for compliance.

**Policy Definition:** is a JSON file used to describe business rules to control access to resources.
**Policy Assigment:** the scope of a policy can effect. Assigned to a user, resource or management group.
**Policy Parameters:** values you can pass into your policy definition so your policies are more flexible for re-use
**Initiative Definitions:** is a collection of policy definitions, that you can assign.

* * *

### Cloud Adoption Framework

1.  Define strategy
2.  Plan
3.  Ready
4.  Adopt
5.  Govern
6.  Manage

* * *

### Well Architected Framework

describe **best practices for building workloads** on Azure categorized into 5 pilars:

1.  **Cost Optimization**: managing costs to maximize the value delivered.
2.  **Operational Excellence**: operations processes that keep a system running in production
3.  **Performance Efficiency**: the ability of a system to adapt to changes in load.
4.  **Reliability**: the ability of a system to recover from failures and continue to function.
5.  **Security**: protecting apps and data from threats

* * *

### Microsoft Security Best Practices - Security Compass

is a collection of best practices that provide clear actionable guidance for security related decisions.

cover the following:

- governance, risk, and compliance
- security operations
- identity and access management
- network security and containment
- information protection and storage
- applications and services

* * *

### SAS - Shared Access Signatures

is a URI that grants restricted access rights to **Azure Storage** resources. Share the URI to grant clients temporary access to specific set of permissions.

Types of shared access signaturs:

- account-level SAS
- Service-level SAS
- User delegation SAS

A shared access signature comes into different formats:

- Ad hoc SAS
- Service SAS with stored access policy

* * *

### CORS - Cross-Origin Resource Sharing

is an HTTP-header based mechanism that allows a server to indicate any other origins (domain, scheme or port) that its own from which a browser should permit loading of resources.
CORS restrict which websites may access data to be loaded onto its page.

- Request Headers
- Response Headers

* * *

### SDL

is an **industry-leading software security assurance process.**
Building security into each **SDL phase** of the development lifecycle helps you catch issues early, and it helps you reduce your development costs.

- training
- requirements
- design
- implementation
- verification
- release
- response
