# DNS Log Analysis Using Splunk SIEM  

## Introduction  
DNS (Domain Name System) logs are essential for monitoring network activity and detecting potential security threats. This project demonstrates the use of **Splunk SIEM (Security Information and Event Management)** to analyze DNS logs, identify anomalies, and enhance cybersecurity measures.  

## Prerequisites  
Before proceeding, ensure the following:  
- A running instance of Splunk installed and configured.  
- DNS log data sources are set up to forward logs to Splunk.  

## Steps to Upload Sample DNS Log Files to Splunk SIEM  

### 1. Prepare Sample DNS Log Files  
- Obtain DNS log files in a suitable format (e.g., `.txt`).  
- Ensure log files include data fields like:  
  - **Source IP**  
  - **Destination IP**  
  - **Domain Name**  
  - **Query Type**  
  - **Response Code**  
- Save these files in a directory accessible by Splunk.  

### 2. Upload Log Files to Splunk  
1. Log in to the Splunk web interface.  
2. Navigate to `Settings > Add Data`.  
3. Select **Upload** as the data input method.  
4. Click **Select File** and upload the prepared DNS log file.  
5. Specify the source type for DNS logs (e.g., `dns`).  
6. Configure other settings such as index, host, and source type.  
7. Click **Submit** to complete the upload.  

### 3. Verify Upload  
- Use the following query in the Splunk search bar to ensure data upload:  
  ```spl
  index=<your_dns_index> sourcetype=<your_dns_sourcetype>
  ```  

## Steps to Analyze DNS Log Files in Splunk SIEM  

### 1. Search for DNS Events  
Run this query to retrieve DNS log events:  
```spl
index=* sourcetype=dns_sample
```  

### 2. Extract Relevant Fields  
Extract fields like **Source IP**, **Destination IP**, and **Domain Name** using regex:  
```spl
index=* sourcetype=dns_sample | regex _raw="(?i)\b(dns|domain|query|response|port 53)\b"
```  

### 3. Identify Anomalies  
Find unusual spikes in DNS activity using the `stats` command:  
```spl
index=* OR index=_* sourcetype=dns_sample | stats count by fqdn
```  

### 4. Find Top DNS Sources  
Identify high-traffic domains and top-requesting IPs:  
```spl
index=* sourcetype=dns_sample | top fqdn, src_ip
```  

### 5. Investigate Suspicious Domains  
Search for domains flagged as malicious:  
```spl
index=* sourcetype=dns_sample fqdn="maliciousdomain.com"
```  

## Conclusion  
Analyzing DNS log files with Splunk SIEM provides actionable insights for detecting anomalies and potential security threats. This analysis strengthens an organization’s overall cybersecurity posture by monitoring and addressing unusual DNS activity effectively.  

## References  
- [Splunk Documentation](https://docs.splunk.com)  
- [VirusTotal](https://www.virustotal.com)  

---  

Let me know if you’d like to further enhance this!
