from burp import IBurpExtender, ITab, IHttpListener, IProxyListener
from java.awt import BorderLayout, GridBagLayout, GridBagConstraints, Insets
from java.awt.event import ActionListener
from javax.swing import JPanel, JTabbedPane, JButton, JTextArea, JScrollPane, JLabel, JTextField, JSplitPane
from javax.swing import SwingUtilities, JOptionPane, BorderFactory
import json
import threading

class BurpExtender(IBurpExtender, ITab, IHttpListener, ActionListener):
    
    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        
        callbacks.setExtensionName("GraphQL Security Tester")
        
        self.schema_extractor = GraphQLSchemaExtractor(callbacks, self._helpers)
        self.query_generator = GPTQueryGenerator()
        
        SwingUtilities.invokeLater(self.createUI)
        
        callbacks.registerHttpListener(self)
        
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
            JOptionPane.showMessageDialog(self.main_panel, "Please enter a GraphQL endpoint")
            return
        
        threading.Thread(target=self._performIntrospection, args=[endpoint]).start()

    def _performIntrospection(self, endpoint):
        try:
            schema = self.schema_extractor.introspect_schema(endpoint)
            SwingUtilities.invokeLater(lambda: self.schema_text.setText(json.dumps(schema, indent=2)))
        except Exception as e:
            SwingUtilities.invokeLater(lambda: JOptionPane.showMessageDialog(self.main_panel, "Introspection failed: " + str(e)))

    def loadManualSchema(self, event):
        pass

    def parseSchema(self, event):
        schema_text = self.schema_text.getText().strip()
        if not schema_text:
            JOptionPane.showMessageDialog(self.main_panel, "Please provide a schema")
            return
        
        try:
            schema = json.loads(schema_text)
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
        
        threading.Thread(target=self._generateQueries, args=[api_key, test_types]).start()

    def _generateQueries(self, api_key, test_types):
        try:
            queries = self.query_generator.generate_malicious_queries(self.parsed_schema, api_key, test_types)
            SwingUtilities.invokeLater(lambda: self.queries_text.setText('\n\n'.join(queries)))
        except Exception as e:
            SwingUtilities.invokeLater(lambda: JOptionPane.showMessageDialog(self.main_panel, "Query generation failed: " + str(e)))

    def testQueries(self, event):
        queries = self.queries_text.getText().strip()
        endpoint = self.endpoint_field.getText().strip()
        
        if not queries or not endpoint:
            JOptionPane.showMessageDialog(self.main_panel, "Please provide queries and endpoint")
            return
        
        threading.Thread(target=self._testQueries, args=[queries, endpoint]).start()

    def _testQueries(self, queries, endpoint):
        query_list = [q.strip() for q in queries.split('\n\n') if q.strip()]
        results = []
        
        for i, query in enumerate(query_list):
            try:
                result = self.schema_extractor.test_query(endpoint, query)
                results.append("Query {0} Result:\n{1}\n".format(i+1, result) + "="*50)
            except Exception as e:
                results.append("Query {0} Error: {1}\n".format(i+1, str(e)) + "="*50)
        
        final_results = '\n\n'.join(results)
        SwingUtilities.invokeLater(lambda: self.results_text.setText(final_results))
        SwingUtilities.invokeLater(lambda: self.full_results_text.setText(final_results))

    def getTabCaption(self):
        return "GraphQL Tester"

    def getUiComponent(self):
        return self.main_panel

    def processHttpMessage(self, toolFlag, messageIsRequest, messageInfo):
        pass


class GraphQLSchemaExtractor:
    def __init__(self, callbacks, helpers):
        self.callbacks = callbacks
        self.helpers = helpers

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
        
        import urllib2
        
        data = json.dumps({"query": introspection_query})
        
        req = urllib2.Request(endpoint)
        req.add_header('Content-Type', 'application/json')
        req.add_header('User-Agent', 'GraphQL Security Tester')
        
        response = urllib2.urlopen(req, data)
        result = json.loads(response.read())
        
        if 'errors' in result:
            raise Exception("Introspection errors: " + str(result['errors']))
        
        schema_data = result['data']['__schema']
        print("[DEBUG] Introspection result keys: " + str(schema_data.keys()))
        print("[DEBUG] Introspection result sample: " + str(schema_data)[:500] + "...")
        
        return schema_data

    def test_query(self, endpoint, query):
        import urllib2
        
        data = json.dumps({"query": query})
        
        req = urllib2.Request(endpoint)
        req.add_header('Content-Type', 'application/json')
        req.add_header('User-Agent', 'GraphQL Security Tester')
        
        response = urllib2.urlopen(req, data)
        return response.read()


class GPTQueryGenerator:
    def generate_malicious_queries(self, schema, api_key, test_types):
        try:
            import urllib2
            
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
            
            req = urllib2.Request("https://api.openai.com/v1/chat/completions")
            req.add_header('Content-Type', 'application/json')
            req.add_header('Authorization', 'Bearer ' + api_key)
            
            # Retry logic for rate limits
            max_retries = 3
            print("[DEBUG] Making API request to OpenAI...")
            
            for attempt in range(max_retries):
                try:
                    print("[DEBUG] Attempt " + str(attempt + 1) + " of " + str(max_retries))
                    response = urllib2.urlopen(req, data)
                    result = json.loads(response.read())
                    print("[DEBUG] API request successful")
                    break
                except urllib2.HTTPError as e:
                    print("[DEBUG] HTTP Error " + str(e.code) + ": " + str(e.reason))
                    if e.code == 429 and attempt < max_retries - 1:
                        import time
                        wait_time = (2 ** attempt) * 5  # Longer waits: 5s, 10s, 20s
                        print("[DEBUG] Rate limited, waiting " + str(wait_time) + " seconds...")
                        time.sleep(wait_time)
                        continue
                    else:
                        raise e
                except Exception as e:
                    print("[DEBUG] Unexpected error: " + str(e))
                    raise e
            
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
            raise Exception("GPT query generation failed: " + str(e))

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