package cve

import (
	"regexp"
	"sort"
)

var RawData = `CVE-2022-49168 

Important 

kernel-headers 

4.14.355 

0:5.15.180-123.192.amzn2 

2025-06-13 

CVE-2025-21796 

Important 

kernel-headers 

4.14.355 

0:5.15.179-121.185.amzn2 

2025-06-13 

CVE-2024-50301 

Important 

kernel-headers 

4.14.355 

0:5.15.173-118.169.amzn2 

2025-06-13 

CVE-2025-31650 

High 

org.apache.tomcat.embed:tomcat-embed-core 

10.1.36 

11.0.6 

2025-05-30 

CVE-2025-21920 

Important 

kernel-headers 

4.14.355 

0:5.15.179-121.185.amzn2 

2025-06-13 

CVE-2023-52975 

Important 

kernel-headers 

4.14.355 

0:5.10.236-227.928.amzn2 

2025-06-13 

CVE-2022-49413 

Important 

kernel-headers 

4.14.355 

0:5.15.50-23.125.amzn2 

2025-06-13 

CVE-2024-47745 

Important 

kernel-headers 

4.14.355 

0:5.15.180-122.191.amzn2 

2025-06-13 

CVE-2025-22004 

Important 

kernel-headers 

4.14.355 

0:5.10.236-227.928.amzn2 

2025-06-13 

CVE-2025-31651 

Critical 

org.apache.tomcat.embed:tomcat-embed-core 

10.1.36 

11.0.6 

2025-05-30 

CVE-2025-21858 

Important 

kernel-headers 

4.14.355 

0:5.15.179-121.185.amzn2 

2025-05-31 

CVE-2024-49882 

Important 

kernel-headers 

4.14.355 

0:5.15.168-114.166.amzn2 

2025-06-13 

CVE-2025-27820 

High 

org.apache.httpcomponents.client5:httpclient5, org.apache.httpcomponents.client5:httpclient5 

5.4.2, 5.4.2 

5.4.3, 5.4.3 

2025-05-24 

CVE-2022-49465 

Important 

kernel-headers 

4.14.355 

0:5.15.180-122.191.amzn2 

2025-06-13 

CVE-2025-21759 

Important 

kernel-headers 

4.14.355 

0:5.15.180-122.191.amzn2 

2025-06-13 

CVE-2024-50036 

Important 

kernel-headers 

4.14.355 

0:5.15.173-118.169.amzn2 

2025-06-13 

CVE-2024-50278 

Important 

kernel-headers 

4.14.355 

0:5.15.173-118.169.amzn2 

2025-06-13 

CVE-2025-22235 

High 

org.springframework.boot:spring-boot, org.springframework.boot:spring-boot-actuator-autoconfigure 

3.4.4, 3.4.4 

3.4.5, 3.4.5 

2025-05-29 

CVE-2025-21791 

Important 

kernel-headers 

4.14.355 

0:5.15.179-121.185.amzn2 

20`

var rxCVE = regexp.MustCompile(`(?i)\bcve\-[0-9]+\-[0-9]+`)

func ParseCVEIDs(s string) []string {
	out := rxCVE.FindAllString(s, -1)
	sort.Strings(out)
	return out
}
