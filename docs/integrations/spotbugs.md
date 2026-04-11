# SpotBugs Integration

Integration with [SpotBugs](https://spotbugs.github.io/), a static analysis tool for Java.

## Installation

```go
import "github.com/grokify/govex/analyzers/spotbugs"
```

## Overview

SpotBugs is the successor to FindBugs, providing static analysis for Java bytecode. The GoVEX integration converts SpotBugs XML output to the GoVEX vulnerability format, focusing on security-related findings.

## Supported Features

- Security bug pattern detection
- CWE mapping
- Severity classification
- Source code location tracking

## Usage

### Parse SpotBugs Output

```go
// Run SpotBugs with XML output
// spotbugs -xml -output results.xml target/classes

// Parse the results
results, err := spotbugs.ParseFile("results.xml")
if err != nil {
    log.Fatal(err)
}

// Convert to GoVEX vulnerabilities
vulns := results.ToVulnerabilities()
```

### Filter Security Issues

```go
// SpotBugs includes many bug types
// Filter to security-relevant findings
securityVulns := vulns.FilterCategory(govex.CategorySAST)
```

## Running SpotBugs

### Maven Integration

```xml
<plugin>
    <groupId>com.github.spotbugs</groupId>
    <artifactId>spotbugs-maven-plugin</artifactId>
    <version>4.8.3</version>
    <configuration>
        <xmlOutput>true</xmlOutput>
        <includeFilterFile>spotbugs-security.xml</includeFilterFile>
    </configuration>
</plugin>
```

```bash
mvn spotbugs:spotbugs
```

### Gradle Integration

```groovy
plugins {
    id "com.github.spotbugs" version "6.0.7"
}

spotbugs {
    toolVersion = '4.8.3'
}

tasks.withType(SpotBugsTask) {
    reports {
        xml.required = true
    }
}
```

### Standalone

```bash
spotbugs -xml -output results.xml target/classes
```

## Security Plugins

For security-focused analysis, use Find Security Bugs:

```xml
<plugin>
    <groupId>com.github.spotbugs</groupId>
    <artifactId>spotbugs-maven-plugin</artifactId>
    <configuration>
        <plugins>
            <plugin>
                <groupId>com.h3xstream.findsecbugs</groupId>
                <artifactId>findsecbugs-plugin</artifactId>
                <version>1.12.0</version>
            </plugin>
        </plugins>
    </configuration>
</plugin>
```

## Field Mapping

| SpotBugs Field | GoVEX Field |
|----------------|-------------|
| `BugInstance.type` | `ID` |
| `BugInstance.message` | `Title` |
| `BugInstance.priority` | `Severity` |
| `SourceLine.sourcepath` | `Location.File` |
| `SourceLine.start` | `Location.Line` |

## Related

- [Integrations Overview](index.md)
- [Semgrep Integration](semgrep.md)
