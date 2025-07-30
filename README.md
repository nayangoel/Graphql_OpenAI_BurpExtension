# GraphQL Security Tester - Burp Suite Extension

A Burp Suite extension that extracts GraphQL schemas and uses GPT to generate malicious test queries for security testing.

## Features

- **Schema Extraction**: Two methods supported
  - Automatic introspection of GraphQL endpoints
  - Manual schema input/upload
- **GPT-Powered Query Generation**: Two modes available:
  - **Bulk Generation**: Generates multiple malicious queries targeting common vulnerabilities
  - **Single Query Pentest**: Generate malicious variants of a specific target query/mutation
- **Advanced Security Testing**: Tests for:
  - SQL injection attempts
  - Authorization bypass
  - DoS via deep nesting
  - Information disclosure
  - Input validation bypass
  - Data exfiltration
- **Query Testing**: Execute generated queries against endpoints
- **Results Analysis**: View detailed test results

## Installation

1. Download the extension file: `GraphQLSecurityTester.py`
2. Open Burp Suite
3. Go to Extensions → Installed → Add
4. Select "Python" as extension type
5. Select the `GraphQLSecurityTester.py` file
6. Click "Next" to load the extension

## Usage

### Schema Extraction

**Method 1: Introspection**
1. Enter your GraphQL endpoint URL
2. Click "Introspect Schema"
3. The schema will be automatically extracted and displayed

**Method 2: Manual Input**
1. Paste your GraphQL schema JSON in the text area
2. Click "Parse Schema"

### Query Generation

**Single Query Pentest Mode (Recommended):**
1. Paste a specific GraphQL query/mutation in the "Target Query/Mutation to Test" field
2. Enter your OpenAI API key
3. Specify test types (e.g., "SQL Injection, Authorization Bypass, DoS")
4. Click "Generate Malicious Queries" to create variants of your target query
5. Review the generated malicious variants

**Bulk Generation Mode:**
1. Leave the target query field empty or with default comments
2. Enter your OpenAI API key
3. Specify test types (e.g., "SQL Injection, Authorization Bypass, DoS")
4. Click "Generate Malicious Queries" to generate multiple test queries
5. Review the generated queries

### Testing

1. Click "Test Queries" to execute against the endpoint
2. View results in the Results tab

## Security Notice

This tool is designed for authorized security testing only. Use responsibly and only on systems you own or have permission to test.

## Requirements

- Burp Suite Professional or Community
- Python/Jython support in Burp
- OpenAI API key for query generation