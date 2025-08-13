# GraphQL Security Tester - Burp Suite Extension

A comprehensive Burp Suite extension that extracts GraphQL schemas and uses LLM models to generate sophisticated malicious test queries for security testing. Features advanced RAG integration, custom message capabilities, and intelligent query formatting.

## Features

### Core Functionality
- **Schema Extraction**: Two methods supported
  - Automatic introspection of GraphQL endpoints
  - Manual schema input/upload
- **LLM-Powered Query Generation**: Two modes available:
  - **Bulk Generation**: Generates multiple malicious queries targeting common vulnerabilities
  - **Single Query Pentest**: Generate malicious variants of a specific target query/mutation
- **Advanced Security Testing**: Tests for:
  - SQL injection attempts
  - Authorization bypass
  - DoS via deep nesting
  - Information disclosure
  - Input validation bypass
  - Data exfiltration
  - NoSQL injection
  - Time-based attacks
  - Field access bypasses
  - Rate limiting vulnerabilities
- **Query Testing**: Execute generated queries against endpoints
- **Results Analysis**: View detailed test results

### Advanced Features
- **Single-Line Query Format**: Automatically converts multi-line GraphQL queries to single-line format while preserving attack descriptions and explanatory text
- **Custom Message Interface**: Send direct messages to the LLM from within Burp Suite for enhanced testing scenarios
- **External RAG Integration**: Integrate with external RAG (Retrieval-Augmented Generation) services with Maximum Marginal Relevance (MMR) search for diverse security knowledge
- **Smart Query Extraction**: Intelligent parsing of LLM responses that preserves both GraphQL queries and their explanatory context
- **Unicode Handling**: Robust Unicode character processing for international content
- **Caching System**: Prevents duplicate expensive operations and RAG queries
- **Fallback HTTP Support**: Multiple HTTP approaches for reliable external service connectivity

## Installation

1. Download the extension file: `GraphQLSecurityTester.py`
2. Open Burp Suite
3. Go to Extensions → Installed → Add
4. Select "Python" as extension type
5. Select the `GraphQLSecurityTester.py` file
6. Click "Next" to load the extension

## Usage

### Initial Setup

1. **Configure LLM Endpoint**: Enter your LLM API endpoint (e.g., `https://api.openai.com/v1/chat/completions`)
2. **Set Model Name**: Specify your model (e.g., `gpt-4`, `gpt-3.5-turbo`)
3. **Add API Key**: Enter your LLM API key
4. **Optional - RAG Integration**: 
   - Configure external RAG endpoint (e.g., `http://localhost:50001`)
   - Set RAG Lambda multiplier (0.0=diversity, 1.0=relevance, default=0.7)
   - Set RAG Documents count (number to retrieve, default=5, range=1-20)

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
2. Specify test types (e.g., "SQL Injection, Authorization Bypass, DoS")
3. Click "Generate Malicious Queries" to create variants of your target query
4. Review the generated malicious variants in single-line format with attack descriptions

**Bulk Generation Mode:**
1. Leave the target query field empty or with default comments
2. Specify test types (e.g., "SQL Injection, Authorization Bypass, DoS")
3. Click "Generate Malicious Queries" to generate multiple test queries
4. Review the generated queries

### Custom Message Interface

**Send Direct Messages to LLM:**
1. Enter your custom message in the "Custom Message to LLM" text area
2. Examples:
   - "Focus on testing for NoSQL injection vulnerabilities"
   - "Generate variants that test for specific field access bypasses"
   - "Create queries that test rate limiting and resource exhaustion"
3. Click "Send Custom Message"
4. The LLM will respond with tailored security advice or queries

### External RAG Integration

**Configure RAG Service:**
1. Ensure your RAG service is running (e.g., at `http://localhost:50001`)
2. Enter the RAG endpoint URL in the configuration field
3. Configure the RAG Lambda multiplier:
   - **0.0**: Maximum diversity (different document sources)
   - **0.3**: Mostly diversity, some relevance  
   - **0.7**: Balanced relevance and diversity *(recommended)*
   - **1.0**: Maximum relevance (similar to traditional search)
4. Configure the number of RAG documents to retrieve:
   - **1-5**: Focused, highly relevant results
   - **5-10**: Balanced coverage *(recommended)*
   - **10-20**: Comprehensive coverage for complex scenarios
5. The extension will automatically query your RAG for relevant security knowledge using MMR search
6. RAG results are integrated into LLM prompts for enhanced testing

### Testing

1. Click "Test Queries" to execute against the endpoint
2. View results in the Results tab
3. Results show both successful responses and error conditions

### Query Format Features

- **Single-Line Output**: All generated GraphQL queries are automatically converted to single-line format for easy copying
- **Attack Descriptions**: Each query variant includes detailed explanations of the attack vector being tested
- **Context Preservation**: Explanatory text from the LLM is preserved alongside the formatted queries

## Security Notice

This tool is designed for authorized security testing only. Use responsibly and only on systems you own or have permission to test.

## Technical Specifications

### System Requirements
- Burp Suite Professional or Community Edition
- Python/Jython support in Burp Suite
- Network connectivity for LLM API calls

### LLM Support
- **OpenAI Models**: GPT-4, GPT-3.5-turbo, and other chat completion models
- **Custom Endpoints**: Any OpenAI-compatible API endpoint
- **API Key**: Required for LLM functionality

### RAG Integration
- **External RAG Services**: HTTP-based RAG services with REST API
- **Supported Endpoints**: `/similarity_search` endpoint with JSON payload
- **Fallback Support**: Multiple HTTP libraries for reliable connectivity
- **Response Format**: JSON responses with `results` array containing `content` and `metadata` fields

### Data Processing
- **Unicode Support**: Full Unicode character handling and normalization
- **Query Parsing**: Advanced regex-based GraphQL query extraction
- **Response Caching**: In-memory caching to prevent duplicate API calls
- **Error Handling**: Comprehensive error handling with fallback mechanisms

## Configuration

### LLM Configuration
```
LLM Endpoint: https://api.openai.com/v1/chat/completions
Model Name: gpt-4
API Key: sk-your-api-key-here
```

### RAG Configuration
```
RAG Endpoint: http://localhost:50001
RAG Lambda: 0.7 (0.0=diversity, 1.0=relevance)
RAG Documents: 5 (number to retrieve, range=1-20)
API Format: POST /similarity_search
Payload: {"query": "text", "k": 5, "search_type": "mmr", "fetch_k": 15, "lambda_mult": 0.7}
Response: {"results": [{"content": "...", "metadata": {...}}]}
```

#### RAG Search Parameters
- **search_type**: "mmr" for Maximum Marginal Relevance (diverse results)
- **k**: Number of documents to retrieve (configurable via UI, default: 5, range: 1-20)
- **fetch_k**: Candidates to fetch for MMR selection (automatically set to k*3)
- **lambda_mult**: Relevance vs diversity balance (configurable via UI, default: 0.7, range: 0.0-1.0)

### Advanced Settings
- **Request Timeout**: 10 seconds for external API calls
- **Cache Duration**: Session-based caching (cleared on restart)
- **Maximum Query Length**: 2000 characters for LLM requests
- **Unicode Normalization**: Automatic replacement of problematic characters

## Troubleshooting

### Common Issues

**RAG Server Not Responding:**
- Verify RAG service is running on specified port
- Check network connectivity to localhost
- Review Burp Suite proxy settings
- Extension automatically falls back to Python urllib if Burp HTTP fails

**LLM API Errors:**
- Verify API key is correct and active
- Check endpoint URL format
- Ensure sufficient API quota/credits
- Review model name spelling

**Query Format Issues:**
- Extension automatically converts multi-line to single-line format
- Unicode characters are normalized automatically
- GraphQL syntax is preserved during conversion

**Performance Optimization:**
- RAG queries are cached to prevent duplicates
- LLM responses are processed incrementally
- Background threads prevent UI blocking

### Debug Logging
The extension provides comprehensive debug logging in Burp Suite's output:
- `[DEBUG]` messages show processing steps
- RAG integration status and responses
- LLM API call details and responses
- Query extraction and formatting steps

## Security Notice

This tool is designed for authorized security testing only. Use responsibly and only on systems you own or have permission to test.

## Contributing

This extension is designed for defensive security testing. When contributing:
- Focus on detection and testing capabilities
- Ensure all features support authorized testing scenarios
- Add comprehensive error handling and logging
- Follow secure coding practices

## Version History

### Latest Version Features
- Single-line GraphQL query formatting with preserved attack descriptions
- Custom message interface for direct LLM interaction
- External RAG service integration with MMR search for diverse results
- Configurable RAG search parameters (lambda multiplier for relevance/diversity balance)
- Enhanced Unicode character handling for international content
- Improved query extraction with context preservation
- Dual HTTP approach for reliable external connectivity
- Advanced caching system for performance optimization

### Recent Improvements
- Fixed infinite loop issues in custom message processing
- Enhanced RAG connectivity with fallback HTTP methods
- Improved error handling and debugging capabilities
- Added protection against duplicate expensive operations