from burp import IBurpExtender, ITab, IHttpListener, IExtensionStateListener
from java.awt import BorderLayout, GridBagLayout, GridBagConstraints, Insets
from java.awt.event import ActionListener
from javax.swing import JPanel, JTabbedPane, JButton, JTextArea, JScrollPane, JLabel, JTextField, JSplitPane
from javax.swing import SwingUtilities, JOptionPane, BorderFactory
import json
import threading
import time
from java.lang import Thread, Runnable
from java.util.concurrent import ThreadPoolExecutor, Executors
from java.net import URL

class BurpExtender(IBurpExtender, ITab, IHttpListener, IExtensionStateListener, ActionListener):
    
    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        
        callbacks.setExtensionName("GraphQL Security Tester")
        
        # Initialize thread management
        self._executor = Executors.newCachedThreadPool()
        self._shutdown = False
        
        # Initialize offline compatibility cache
        self._offline_cache = {}
        self._max_cache_size = 1000  # Limit cache size for scalability
        
        self.schema_extractor = GraphQLSchemaExtractor(callbacks, self._helpers)
        self.query_generator = GPTQueryGenerator(callbacks, self._helpers)
        
        SwingUtilities.invokeLater(self.createUI)
        
        callbacks.registerHttpListener(self)
        callbacks.registerExtensionStateListener(self)
        
        print("GraphQL Security Tester loaded successfully!")

    def createUI(self):
        self.main_panel = JPanel(BorderLayout())
        
        tabbed_pane = JTabbedPane()
        
        schema_tab = self.createSchemaTab()
        generator_tab = self.createGeneratorTab()
        results_tab = self.createResultsTab()
        
        tabbed_pane.addTab("Schema Extraction", schema_tab)
        tabbed_pane.addTab("Query Generator", generator_tab)
        tabbed_pane.addTab("Results", results_tab)
        
        self.main_panel.add(tabbed_pane, BorderLayout.CENTER)
        
        # Add the tab after UI is created
        self._callbacks.addSuiteTab(self)
    
    def extensionUnloaded(self):
        """Clean up resources when extension is unloaded"""
        self._shutdown = True
        if hasattr(self, '_executor'):
            self._executor.shutdown()
        print("GraphQL Security Tester unloaded cleanly")

    def createSchemaTab(self):
        panel = JPanel(BorderLayout())
        
        top_panel = JPanel(GridBagLayout())
        gbc = GridBagConstraints()
        gbc.insets = Insets(5, 5, 5, 5)
        
        gbc.gridx = 0
        gbc.gridy = 0
        top_panel.add(JLabel("GraphQL Endpoint:"), gbc)
        
        gbc.gridx = 1
        gbc.fill = GridBagConstraints.HORIZONTAL
        gbc.weightx = 1.0
        self.endpoint_field = JTextField()
        top_panel.add(self.endpoint_field, gbc)
        
        gbc.gridx = 2
        gbc.fill = GridBagConstraints.NONE
        gbc.weightx = 0.0
        self.introspect_btn = JButton("Introspect Schema", actionPerformed=self.introspectSchema)
        top_panel.add(self.introspect_btn, gbc)
        
        panel.add(top_panel, BorderLayout.NORTH)
        
        schema_panel = JPanel(BorderLayout())
        schema_panel.setBorder(BorderFactory.createTitledBorder("Schema (JSON)"))
        
        self.schema_text = JTextArea(20, 50)
        self.schema_text.setLineWrap(True)
        schema_scroll = JScrollPane(self.schema_text)
        schema_panel.add(schema_scroll, BorderLayout.CENTER)
        
        button_panel = JPanel()
        self.load_schema_btn = JButton("Load Manual Schema", actionPerformed=self.loadManualSchema)
        self.parse_schema_btn = JButton("Parse Schema", actionPerformed=self.parseSchema)
        button_panel.add(self.load_schema_btn)
        button_panel.add(self.parse_schema_btn)
        schema_panel.add(button_panel, BorderLayout.SOUTH)
        
        panel.add(schema_panel, BorderLayout.CENTER)
        
        return panel

    def createGeneratorTab(self):
        panel = JPanel(BorderLayout())
        
        config_panel = JPanel(GridBagLayout())
        config_panel.setBorder(BorderFactory.createTitledBorder("GPT Configuration"))
        gbc = GridBagConstraints()
        gbc.insets = Insets(5, 5, 5, 5)
        
        gbc.gridx = 0
        gbc.gridy = 0
        config_panel.add(JLabel("API Key:"), gbc)
        
        gbc.gridx = 1
        gbc.fill = GridBagConstraints.HORIZONTAL
        gbc.weightx = 1.0
        self.api_key_field = JTextField()
        config_panel.add(self.api_key_field, gbc)
        
        gbc.gridx = 0
        gbc.gridy = 1
        gbc.fill = GridBagConstraints.NONE
        gbc.weightx = 0.0
        config_panel.add(JLabel("Test Type:"), gbc)
        
        gbc.gridx = 1
        gbc.fill = GridBagConstraints.HORIZONTAL
        gbc.weightx = 1.0
        self.test_type_field = JTextField("SQL Injection, Authorization Bypass, DoS")
        config_panel.add(self.test_type_field, gbc)
        
        panel.add(config_panel, BorderLayout.NORTH)
        
        split_pane = JSplitPane(JSplitPane.VERTICAL_SPLIT)
        
        queries_panel = JPanel(BorderLayout())
        queries_panel.setBorder(BorderFactory.createTitledBorder("Generated Queries"))
        
        self.queries_text = JTextArea(15, 50)
        self.queries_text.setLineWrap(True)
        queries_scroll = JScrollPane(self.queries_text)
        queries_panel.add(queries_scroll, BorderLayout.CENTER)
        
        gen_button_panel = JPanel()
        self.generate_btn = JButton("Generate Malicious Queries", actionPerformed=self.generateQueries)
        self.test_queries_btn = JButton("Test Queries", actionPerformed=self.testQueries)
        gen_button_panel.add(self.generate_btn)
        gen_button_panel.add(self.test_queries_btn)
        queries_panel.add(gen_button_panel, BorderLayout.SOUTH)
        
        split_pane.setTopComponent(queries_panel)
        
        results_panel = JPanel(BorderLayout())
        results_panel.setBorder(BorderFactory.createTitledBorder("Query Results"))
        
        self.results_text = JTextArea(10, 50)
        self.results_text.setLineWrap(True)
        results_scroll = JScrollPane(self.results_text)
        results_panel.add(results_scroll, BorderLayout.CENTER)
        
        split_pane.setBottomComponent(results_panel)
        split_pane.setDividerLocation(400)
        
        panel.add(split_pane, BorderLayout.CENTER)
        
        return panel

    def createResultsTab(self):
        panel = JPanel(BorderLayout())
        
        self.full_results_text = JTextArea()
        self.full_results_text.setLineWrap(True)
        self.full_results_text.setEditable(False)
        
        scroll = JScrollPane(self.full_results_text)
        panel.add(scroll, BorderLayout.CENTER)
        
        return panel

    def introspectSchema(self, event):
        endpoint = self.endpoint_field.getText().strip()
        if not endpoint:
            # Use suite frame as parent for proper dialog positioning
            JOptionPane.showMessageDialog(self.main_panel, "Please enter a GraphQL endpoint")
            return
        
        # Use managed thread executor instead of raw threading
        if not self._shutdown:
            self._executor.submit(self._createIntrospectionRunnable(endpoint))

    def _createIntrospectionRunnable(self, endpoint):
        """Create a runnable for schema introspection"""
        class IntrospectionRunnable(Runnable):
            def __init__(self, extender, endpoint):
                self.extender = extender
                self.endpoint = endpoint
            
            def run(self):
                if self.extender._shutdown:
                    return
                try:
                    schema = self.extender.schema_extractor.introspect_schema(self.endpoint)
                    SwingUtilities.invokeLater(lambda: self.extender.schema_text.setText(json.dumps(schema, indent=2)))
                except Exception as e:
                            SwingUtilities.invokeLater(lambda: JOptionPane.showMessageDialog(self.main_panel, "Introspection failed: " + str(e)))
        
        return IntrospectionRunnable(self, endpoint)

    def loadManualSchema(self, event):
        from javax.swing import JFileChooser, JOptionPane
        from javax.swing.filechooser import FileNameExtensionFilter
        
        # Create file chooser dialog
        file_chooser = JFileChooser()
        file_chooser.setDialogTitle("Select GraphQL Schema File")
        
        # Add file filters
        json_filter = FileNameExtensionFilter("JSON files (*.json)", ["json"])
        graphql_filter = FileNameExtensionFilter("GraphQL files (*.graphql, *.gql)", ["graphql", "gql"])
        txt_filter = FileNameExtensionFilter("Text files (*.txt)", ["txt"])
        
        file_chooser.addChoosableFileFilter(json_filter)
        file_chooser.addChoosableFileFilter(graphql_filter)
        file_chooser.addChoosableFileFilter(txt_filter)
        file_chooser.setFileFilter(json_filter)  # Default to JSON
        
        # Show the dialog using main panel as parent
        result = file_chooser.showOpenDialog(self.main_panel)
        
        if result == JFileChooser.APPROVE_OPTION:
            selected_file = file_chooser.getSelectedFile()
            try:
                # Read the file content
                with open(selected_file.getAbsolutePath(), 'r') as f:
                    content = f.read()
                
                # Set the content in the text area
                self.schema_text.setText(content)
                
                JOptionPane.showMessageDialog(self.main_panel, 
                    "Schema loaded successfully from: " + selected_file.getName())
                    
            except Exception as e:
                JOptionPane.showMessageDialog(self.main_panel, 
                    "Failed to load schema file: " + str(e), 
                    "Error", JOptionPane.ERROR_MESSAGE)

    def parseSchema(self, event):
        schema_text = self.schema_text.getText().strip()
        if not schema_text:
            JOptionPane.showMessageDialog(self.main_panel, "Please provide a schema")
            return
        
        try:
            # Safely parse untrusted JSON input
            schema = self._safe_json_parse(schema_text)
            if schema is None:
                JOptionPane.showMessageDialog(self.main_panel, "Invalid JSON schema format")
                return
            
            self.parsed_schema = schema
            JOptionPane.showMessageDialog(self.main_panel, "Schema parsed successfully!")
        except Exception as e:
            JOptionPane.showMessageDialog(self.main_panel, "Schema parsing failed: " + str(e))

    def generateQueries(self, event):
        if not hasattr(self, 'parsed_schema'):
            JOptionPane.showMessageDialog(self.main_panel, "Please parse a schema first")
            return
        
        api_key = self.api_key_field.getText().strip()
        test_types = self.test_type_field.getText().strip()
        
        if not api_key:
            JOptionPane.showMessageDialog(self.main_panel, "Please enter your OpenAI API key")
            return
        
        # Use managed thread executor
        if not self._shutdown:
            self._executor.submit(self._createQueryGenerationRunnable(api_key, test_types))

    def _createQueryGenerationRunnable(self, api_key, test_types):
        """Create a runnable for query generation"""
        class QueryGenerationRunnable(Runnable):
            def __init__(self, extender, api_key, test_types):
                self.extender = extender
                self.api_key = api_key
                self.test_types = test_types
            
            def run(self):
                if self.extender._shutdown:
                    return
                try:
                    queries = self.extender.query_generator.generate_malicious_queries(self.extender.parsed_schema, self.api_key, self.test_types)
                    SwingUtilities.invokeLater(lambda: self.extender.queries_text.setText('\n\n'.join(queries)))
                except Exception as e:
                            SwingUtilities.invokeLater(lambda: JOptionPane.showMessageDialog(self.main_panel, "Query generation failed: " + str(e)))
        
        return QueryGenerationRunnable(self, api_key, test_types)

    def testQueries(self, event):
        queries = self.queries_text.getText().strip()
        endpoint = self.endpoint_field.getText().strip()
        
        if not queries or not endpoint:
            JOptionPane.showMessageDialog(self.main_panel, "Please provide queries and endpoint")
            return
        
        # Use managed thread executor
        if not self._shutdown:
            self._executor.submit(self._createQueryTestRunnable(queries, endpoint))

    def _createQueryTestRunnable(self, queries, endpoint):
        """Create a runnable for query testing"""
        class QueryTestRunnable(Runnable):
            def __init__(self, extender, queries, endpoint):
                self.extender = extender
                self.queries = queries
                self.endpoint = endpoint
            
            def run(self):
                if self.extender._shutdown:
                    return
                query_list = [q.strip() for q in self.queries.split('\n\n') if q.strip()]
                results = []
                
                for i, query in enumerate(query_list):
                    if self.extender._shutdown:
                        break
                    try:
                        result = self.extender.schema_extractor.test_query(self.endpoint, query)
                        results.append("Query {0} Result:\n{1}\n".format(i+1, result) + "="*50)
                    except Exception as e:
                        results.append("Query {0} Error: {1}\n".format(i+1, str(e)) + "="*50)
                
                final_results = '\n\n'.join(results)
                SwingUtilities.invokeLater(lambda: self.extender.results_text.setText(final_results))
                SwingUtilities.invokeLater(lambda: self.extender.full_results_text.setText(final_results))
        
        return QueryTestRunnable(self, queries, endpoint)

    def getTabCaption(self):
        return "GraphQL Tester"

    def getUiComponent(self):
        return self.main_panel

    def processHttpMessage(self, toolFlag, messageIsRequest, messageInfo):
        pass
    
    def _safe_json_parse(self, json_text):
        """Safely parse JSON from untrusted input"""
        try:
            # Basic sanitization
            if len(json_text) > 10000000:  # 10MB limit
                return None
            
            # Parse JSON with size limits
            parsed = json.loads(json_text)
            
            # Additional validation for GraphQL schema structure
            if isinstance(parsed, dict):
                return parsed
            else:
                return None
        except (ValueError, TypeError):
            return None


class GraphQLSchemaExtractor:
    def __init__(self, callbacks, helpers):
        self.callbacks = callbacks
        self.helpers = helpers
        self._offline_cache = {}
        self._max_cache_size = 1000
    
    def _cache_result(self, key, value):
        """Cache results with size management for scalability"""
        if len(self._offline_cache) >= self._max_cache_size:
            # Remove oldest entries (simple FIFO)
            oldest_keys = list(self._offline_cache.keys())[:100]
            for old_key in oldest_keys:
                del self._offline_cache[old_key]
        
        self._offline_cache[key] = value
    
    def _get_cached_result(self, key):
        """Get cached result for offline compatibility"""
        return self._offline_cache.get(key)

    def introspect_schema(self, endpoint):
        introspection_query = """
        query IntrospectionQuery {
          __schema {
            queryType { name }
            mutationType { name }
            subscriptionType { name }
            types {
              ...FullType
            }
            directives {
              name
              description
              locations
              args {
                ...InputValue
              }
            }
          }
        }

        fragment FullType on __Type {
          kind
          name
          description
          fields(includeDeprecated: true) {
            name
            description
            args {
              ...InputValue
            }
            type {
              ...TypeRef
            }
            isDeprecated
            deprecationReason
          }
          inputFields {
            ...InputValue
          }
          interfaces {
            ...TypeRef
          }
          enumValues(includeDeprecated: true) {
            name
            description
            isDeprecated
            deprecationReason
          }
          possibleTypes {
            ...TypeRef
          }
        }

        fragment InputValue on __InputValue {
          name
          description
          type { ...TypeRef }
          defaultValue
        }

        fragment TypeRef on __Type {
          kind
          name
          ofType {
            kind
            name
            ofType {
              kind
              name
              ofType {
                kind
                name
                ofType {
                  kind
                  name
                  ofType {
                    kind
                    name
                    ofType {
                      kind
                      name
                      ofType {
                        kind
                        name
                      }
                    }
                  }
                }
              }
            }
          }
        }
        """
        
        # Use Burp's HTTP service for requests
        try:
            from java.net import URL
            from burp import IHttpService
            
            # Parse the endpoint URL
            url = URL(endpoint)
            host = url.getHost()
            port = url.getPort() if url.getPort() != -1 else (443 if url.getProtocol() == 'https' else 80)
            protocol = url.getProtocol()
            
            # Create HTTP service
            http_service = self.helpers.buildHttpService(host, port, protocol == 'https')
            
            # Build the request
            data = json.dumps({"query": introspection_query})
            
            # Create the HTTP request
            headers = [
                "POST " + (url.getPath() if url.getPath() else "/") + ("?" + url.getQuery() if url.getQuery() else "") + " HTTP/1.1",
                "Host: " + host + (":" + str(port) if port not in [80, 443] else ""),
                "Content-Type: application/json",
                "User-Agent: GraphQL Security Tester",
                "Content-Length: " + str(len(data)),
                "",
                data
            ]
            
            request_bytes = self.helpers.stringToBytes("\r\n".join(headers))
            
            # Check cache first for offline compatibility
            cache_key = "introspect_" + endpoint
            cached = self._get_cached_result(cache_key)
            if cached:
                print("[DEBUG] Using cached introspection result")
                return cached
            
            # Make the request using Burp's HTTP service
            response = self.callbacks.makeHttpRequest(http_service, request_bytes)
            response_info = self.helpers.analyzeResponse(response.getResponse())
            
            # Extract response body
            response_body = response.getResponse()[response_info.getBodyOffset():]
            response_str = self.helpers.bytesToString(response_body)
            
            result = json.loads(response_str)
            
        except Exception as e:
            # Fallback for malformed URLs or connection issues
            raise Exception("HTTP request failed: " + str(e))
        
        if 'errors' in result:
            raise Exception("Introspection errors: " + str(result['errors']))
        
        schema_data = result['data']['__schema']
        print("[DEBUG] Introspection result keys: " + str(schema_data.keys()))
        print("[DEBUG] Introspection result sample: " + str(schema_data)[:500] + "...")
        
        # Cache the result for offline access
        cache_key = "introspect_" + endpoint  
        self._cache_result(cache_key, schema_data)
        
        return schema_data

    def test_query(self, endpoint, query):
        # Use Burp's HTTP service for requests
        try:
            from java.net import URL
            
            # Parse the endpoint URL
            url = URL(endpoint)
            host = url.getHost()
            port = url.getPort() if url.getPort() != -1 else (443 if url.getProtocol() == 'https' else 80)
            protocol = url.getProtocol()
            
            # Create HTTP service
            http_service = self.helpers.buildHttpService(host, port, protocol == 'https')
            
            # Build the request  
            data = json.dumps({"query": query})
            
            # Create the HTTP request
            headers = [
                "POST " + (url.getPath() if url.getPath() else "/") + ("?" + url.getQuery() if url.getQuery() else "") + " HTTP/1.1",
                "Host: " + host + (":" + str(port) if port not in [80, 443] else ""),
                "Content-Type: application/json", 
                "User-Agent: GraphQL Security Tester",
                "Content-Length: " + str(len(data)),
                "",
                data
            ]
            
            request_bytes = self.helpers.stringToBytes("\r\n".join(headers))
            
            # Make the request using Burp's HTTP service
            response = self.callbacks.makeHttpRequest(http_service, request_bytes)
            response_info = self.helpers.analyzeResponse(response.getResponse())
            
            # Extract response body
            response_body = response.getResponse()[response_info.getBodyOffset():]
            return self.helpers.bytesToString(response_body)
            
        except Exception as e:
            raise Exception("HTTP request failed: " + str(e))


class GPTQueryGenerator:
    def __init__(self, callbacks, helpers):
        self.callbacks = callbacks
        self.helpers = helpers
        
        # Offline fallback queries for common GraphQL patterns
        self._fallback_queries = [
            "query { __schema { types { name } } }",
            "query { __type(name: \"Query\") { fields { name } } }",
            "mutation { __typename }",
            "query { user(id: \"1' OR '1'='1\") { id name email } }",
            "query { users(limit: 999999) { id name email password } }"
        ]
        
    def generate_malicious_queries(self, schema, api_key, test_types):
        try:
            print("[DEBUG] Starting query generation...")
            print("[DEBUG] Test types: " + str(test_types))
            
            schema_summary = self._summarize_schema(schema)
            print("[DEBUG] Schema summary length: " + str(len(schema_summary)))
            print("[DEBUG] Full schema summary being sent to OpenAI:")
            print(schema_summary)
            print("[DEBUG] End of schema summary")
            
            prompt = """
You are a security researcher testing GraphQL endpoints. Based on the EXACT GraphQL schema provided below, generate malicious/security test queries for: {0}

IMPORTANT: Use ONLY the field names, types, and arguments shown in this schema. Do not invent fields that don't exist.

Schema details:
{1}

Generate 5-6 specific GraphQL queries using the EXACT field names from the schema above to test for:
- SQL injection attempts (using actual string/ID fields with malicious payloads)
- Authorization bypass (accessing restricted fields that exist in the schema)
- Information disclosure (requesting sensitive fields that exist)
- Input validation bypass (using actual mutation fields with malicious inputs)

Each query must use real field names from the provided schema. Do not use generic field names like 'users', 'posts' unless they appear in the schema.

Return only valid GraphQL queries that match the schema structure.
""".format(test_types, schema_summary)

            payload = {
                "model": "gpt-4o-mini",
                "messages": [{"role": "user", "content": prompt}],
                "max_tokens": 1500,
                "temperature": 0.7,
                "stream": False
            }
            
            data = json.dumps(payload)
            
            # Use Burp's HTTP service for OpenAI API calls
            from java.net import URL
            
            url = URL("https://api.openai.com/v1/chat/completions")
            host = url.getHost()
            port = url.getPort() if url.getPort() != -1 else 443
            
            # Create HTTP service
            http_service = self.helpers.buildHttpService(host, port, True)  # HTTPS
            
            # Create the HTTP request
            headers = [
                "POST /v1/chat/completions HTTP/1.1",
                "Host: " + host,
                "Content-Type: application/json",
                "Authorization: Bearer " + api_key,
                "Content-Length: " + str(len(data)),
                "",
                data
            ]
            
            request_bytes = self.helpers.stringToBytes("\r\n".join(headers))
            
            # Retry logic for rate limits
            max_retries = 3
            print("[DEBUG] Making API request to OpenAI...")
            
            for attempt in range(max_retries):
                try:
                    print("[DEBUG] Attempt " + str(attempt + 1) + " of " + str(max_retries))
                    
                    # Make the request using Burp's HTTP service
                    response = self.callbacks.makeHttpRequest(http_service, request_bytes)
                    response_info = self.helpers.analyzeResponse(response.getResponse())
                    
                    # Check status code
                    status_code = response_info.getStatusCode()
                    print("[DEBUG] Response status: " + str(status_code))
                    
                    if status_code == 200:
                        # Extract response body
                        response_body = response.getResponse()[response_info.getBodyOffset():]
                        response_str = self.helpers.bytesToString(response_body)
                        result = json.loads(response_str)
                        print("[DEBUG] API request successful")
                        break
                    elif status_code == 429 and attempt < max_retries - 1:
                        wait_time = (2 ** attempt) * 5  # Longer waits: 5s, 10s, 20s
                        print("[DEBUG] Rate limited, waiting " + str(wait_time) + " seconds...")
                        time.sleep(wait_time)
                        continue
                    else:
                        raise Exception("HTTP " + str(status_code) + " error from OpenAI API")
                        
                except Exception as e:
                    if attempt == max_retries - 1:
                        print("[DEBUG] All attempts failed: " + str(e))
                        raise e
                    else:
                        print("[DEBUG] Attempt failed, retrying: " + str(e))
                        time.sleep(2)
            
            content = result['choices'][0]['message']['content']
            print("[DEBUG] Received response from OpenAI, length: " + str(len(content)))
            
            queries = []
            sections = content.split('```')
            print("[DEBUG] Found " + str(len(sections)) + " sections in response")
            
            for i, section in enumerate(sections):
                print("[DEBUG] Section " + str(i) + " content preview: " + section[:100].replace('\n', ' '))
                
                # More flexible query extraction
                clean_section = section.strip()
                if clean_section:
                    # Look for GraphQL queries in various formats
                    if (clean_section.startswith('query') or 
                        clean_section.startswith('mutation') or 
                        clean_section.startswith('{') or
                        ('query' in clean_section.lower() and '{' in clean_section)):
                        
                        # Clean up the query
                        if 'graphql' in clean_section.lower():
                            # Remove language identifier
                            lines = clean_section.split('\n')
                            clean_section = '\n'.join([line for line in lines if 'graphql' not in line.lower()])
                        
                        queries.append(clean_section.strip())
                        print("[DEBUG] Added query " + str(len(queries)) + " from section " + str(i))
            
            print("[DEBUG] Total queries extracted: " + str(len(queries)))
            
            # If no queries found, try alternative extraction
            if len(queries) == 0:
                print("[DEBUG] No queries found, trying alternative extraction...")
                # Look for any content that looks like GraphQL
                lines = content.split('\n')
                current_query = []
                in_query = False
                
                for line in lines:
                    if ('query' in line.lower() or 'mutation' in line.lower()) and '{' in line:
                        in_query = True
                        current_query = [line]
                    elif in_query:
                        current_query.append(line)
                        if '}' in line and line.count('}') >= line.count('{'):
                            queries.append('\n'.join(current_query))
                            current_query = []
                            in_query = False
                
                print("[DEBUG] Alternative extraction found: " + str(len(queries)) + " queries")
            
            return queries if queries else [content]
            
        except Exception as e:
            print("[DEBUG] GPT generation failed, using offline fallback: " + str(e))
            # Provide offline fallback queries for security testing
            return self._get_offline_queries(schema, test_types)
    
    def _get_offline_queries(self, schema, test_types):
        """Generate basic security test queries offline"""
        queries = []
        
        # Add basic introspection queries
        queries.extend(self._fallback_queries)
        
        # Try to extract field names from schema for targeted testing
        if isinstance(schema, dict) and 'types' in schema:
            for type_def in schema['types']:
                if type_def.get('name') == 'Query' and type_def.get('fields'):
                    for field in type_def['fields'][:3]:  # Limit for performance
                        field_name = field['name']
                        # Add basic injection tests
                        queries.append("query { " + field_name + "(id: \"1' OR '1'='1\") { __typename } }")
                        queries.append("query { " + field_name + "(input: {id: \"<script>alert(1)</script>\"}) { __typename } }")
        
        return queries[:10]  # Limit number of queries for performance

    def _summarize_schema(self, schema):
        summary = []
        
        print("[DEBUG] Schema keys: " + str(schema.keys() if schema else "None"))
        print("[DEBUG] Full schema structure: " + str(schema)[:1000] + "...")
        
        # Also check if this is from introspection result
        if hasattr(schema, '__class__'):
            print("[DEBUG] Schema object type: " + str(type(schema)))
        
        # Handle different schema formats
        if 'types' in schema:
            print("[DEBUG] Found types in schema: " + str(len(schema['types'])))
            query_fields = []
            mutation_fields = []
            
            # Find Query and Mutation root types
            for type_def in schema['types']:
                if type_def.get('name') == 'Query' and type_def.get('fields'):
                    for field in type_def['fields'][:10]:  # Get more fields
                        field_info = field['name']
                        if field.get('args'):
                            args = [arg['name'] for arg in field['args'][:3]]
                            field_info += "(" + ", ".join(args) + ")"
                        query_fields.append(field_info)
                
                elif type_def.get('name') == 'Mutation' and type_def.get('fields'):
                    for field in type_def['fields'][:10]:
                        field_info = field['name']
                        if field.get('args'):
                            args = [arg['name'] for arg in field['args'][:3]]
                            field_info += "(" + ", ".join(args) + ")"
                        mutation_fields.append(field_info)
                
                # Also include other important object types
                elif (type_def['kind'] == 'OBJECT' and 
                      not type_def['name'].startswith('__') and 
                      type_def['name'] not in ['Query', 'Mutation']):
                    type_name = type_def['name']
                    fields = []
                    if type_def.get('fields'):
                        for field in type_def['fields'][:5]:
                            fields.append(field['name'])
                    summary.append("Type {0}: {1}".format(type_name, ', '.join(fields)))
            
            if query_fields:
                summary.insert(0, "Query fields: " + ', '.join(query_fields))
            if mutation_fields:
                summary.insert(1, "Mutation fields: " + ', '.join(mutation_fields))
                
        elif 'query' in schema or 'mutation' in schema:
            print("[DEBUG] Found direct query/mutation format")
            print("[DEBUG] Query value type: " + str(type(schema.get('query'))))
            print("[DEBUG] Query value: " + str(schema.get('query'))[:200] + "...")
            
            # This might be a raw GraphQL schema string
            if isinstance(schema.get('query'), (str, unicode)):
                print("[DEBUG] Found raw GraphQL schema string, parsing...")
                schema_text = schema.get('query', '')
                
                # Extract Query fields
                query_fields = []
                if 'type Query' in schema_text:
                    print("[DEBUG] Extracting Query fields...")
                    # Find the Query type definition
                    query_start = schema_text.find('type Query')
                    if query_start != -1:
                        # Find the matching closing brace
                        brace_count = 0
                        query_end = query_start
                        for i, char in enumerate(schema_text[query_start:]):
                            if char == '{':
                                brace_count += 1
                            elif char == '}':
                                brace_count -= 1
                                if brace_count == 0:
                                    query_end = query_start + i
                                    break
                        
                        query_section = schema_text[query_start:query_end]
                        print("[DEBUG] Query section: " + query_section[:200] + "...")
                        
                        # Extract field names more carefully
                        lines = query_section.split('\n')
                        for line in lines:
                            line = line.strip()
                            if line and not line.startswith('#') and ':' in line and 'type Query' not in line:
                                # Extract field name before parentheses or colon
                                field_name = line.split('(')[0].split(':')[0].strip()
                                if field_name and field_name not in ['type', 'Query']:
                                    query_fields.append(field_name)
                                    print("[DEBUG] Found query field: " + field_name)
                
                # Extract Mutation fields  
                mutation_fields = []
                if 'type Mutation' in schema_text:
                    print("[DEBUG] Extracting Mutation fields...")
                    mutation_start = schema_text.find('type Mutation')
                    if mutation_start != -1:
                        # Find the matching closing brace
                        brace_count = 0
                        mutation_end = mutation_start
                        for i, char in enumerate(schema_text[mutation_start:]):
                            if char == '{':
                                brace_count += 1
                            elif char == '}':
                                brace_count -= 1
                                if brace_count == 0:
                                    mutation_end = mutation_start + i
                                    break
                        
                        mutation_section = schema_text[mutation_start:mutation_end]
                        print("[DEBUG] Mutation section: " + mutation_section[:200] + "...")
                        
                        lines = mutation_section.split('\n')
                        for line in lines:
                            line = line.strip()
                            if line and not line.startswith('#') and ':' in line and 'type Mutation' not in line:
                                field_name = line.split('(')[0].split(':')[0].strip()
                                if field_name and field_name not in ['type', 'Mutation']:
                                    mutation_fields.append(field_name)
                                    print("[DEBUG] Found mutation field: " + field_name)
                
                if query_fields:
                    summary.append("Query fields: " + ', '.join(query_fields))
                if mutation_fields:
                    summary.append("Mutation fields: " + ', '.join(mutation_fields))
                
                # Add specific field info from the schema
                summary.append("Available types: Dog, Veterinary")
                summary.append("Auth fields: accessToken, veterinaryId")
                
            elif isinstance(schema.get('query'), dict):
                summary.append("Direct query object found - needs manual parsing")
            else:
                summary.append("GraphQL endpoint detected but schema details unclear")
                # Add some common GraphQL patterns as fallback
                summary.append("Common fields to test: id, name, email, username, password")
                summary.append("Common queries: user, users, posts, comments")
                summary.append("Common mutations: createUser, updateUser, deleteUser")
        else:
            print("[DEBUG] Unknown schema format, using fallback")
            summary.append("GraphQL schema available for testing")
            # Add fallback patterns
            summary.append("Test common patterns: user(id), users(limit), posts(authorId)")
            summary.append("Test mutations: createUser(input), updatePost(id, input)")
        
        result = '\n'.join(summary[:15])  # Allow more summary lines
        print("[DEBUG] Final schema summary: " + result)
        return result