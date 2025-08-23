from burp import IBurpExtender, ITab, IHttpListener, IExtensionStateListener, IContextMenuFactory, IContextMenuInvocation
from java.awt import BorderLayout, GridBagLayout, GridBagConstraints, Insets
from java.awt.event import ActionListener
from javax.swing import JPanel, JTabbedPane, JButton, JTextArea, JScrollPane, JLabel, JTextField, JSplitPane, JMenuItem
from javax.swing import SwingUtilities, JOptionPane, BorderFactory
import json
import threading
import time
from java.lang import Thread, Runnable
from java.util.concurrent import ThreadPoolExecutor, Executors
from java.net import URL

class BurpExtender(IBurpExtender, ITab, IHttpListener, IExtensionStateListener, IContextMenuFactory, ActionListener):
    
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
        callbacks.registerContextMenuFactory(self)
        
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
        config_panel.setBorder(BorderFactory.createTitledBorder("LLM Configuration"))
        gbc = GridBagConstraints()
        gbc.insets = Insets(5, 5, 5, 5)
        
        gbc.gridx = 0
        gbc.gridy = 0
        gbc.fill = GridBagConstraints.NONE
        gbc.weightx = 0.0
        config_panel.add(JLabel("LLM Endpoint:"), gbc)
        
        gbc.gridx = 1
        gbc.fill = GridBagConstraints.HORIZONTAL
        gbc.weightx = 1.0
        self.llm_endpoint_field = JTextField("http://192.168.86.199:1234/v1/chat/completions")
        config_panel.add(self.llm_endpoint_field, gbc)
        
        gbc.gridx = 0
        gbc.gridy = 1
        gbc.fill = GridBagConstraints.NONE
        gbc.weightx = 0.0
        config_panel.add(JLabel("Model Name:"), gbc)
        
        gbc.gridx = 1
        gbc.fill = GridBagConstraints.HORIZONTAL
        gbc.weightx = 1.0
        self.model_name_field = JTextField("llama3:8b")
        config_panel.add(self.model_name_field, gbc)
        
        gbc.gridx = 0
        gbc.gridy = 2
        gbc.fill = GridBagConstraints.NONE
        gbc.weightx = 0.0
        config_panel.add(JLabel("API Key (Optional):"), gbc)
        
        gbc.gridx = 1
        gbc.fill = GridBagConstraints.HORIZONTAL
        gbc.weightx = 1.0
        self.api_key_field = JTextField()
        config_panel.add(self.api_key_field, gbc)
        
        gbc.gridx = 0
        gbc.gridy = 3
        gbc.fill = GridBagConstraints.NONE
        gbc.weightx = 0.0
        config_panel.add(JLabel("Test Type:"), gbc)
        
        gbc.gridx = 1
        gbc.fill = GridBagConstraints.HORIZONTAL
        gbc.weightx = 1.0
        self.test_type_field = JTextField("Graphql, query, mutation, alias, learn, SQL Injection, Authorization Bypass, DoS, Cross site Scripting, Command Injection, Log Injection, HTML Injection, Server Side Request Forgery, Field Duplication attack")
        config_panel.add(self.test_type_field, gbc)
        
        gbc.gridx = 0
        gbc.gridy = 4
        gbc.fill = GridBagConstraints.NONE
        gbc.weightx = 0.0
        config_panel.add(JLabel("RAG Endpoint (Optional):"), gbc)
        
        gbc.gridx = 1
        gbc.fill = GridBagConstraints.HORIZONTAL
        gbc.weightx = 1.0
        self.rag_endpoint_field = JTextField("http://localhost:50001")
        config_panel.add(self.rag_endpoint_field, gbc)
        
        # RAG Lambda Multiplier (relevance vs diversity balance)
        gbc.gridx = 0
        gbc.gridy = 5
        gbc.fill = GridBagConstraints.NONE
        gbc.weightx = 0.0
        config_panel.add(JLabel("RAG Lambda (0.0=diversity, 1.0=relevance):"), gbc)
        
        gbc.gridx = 1
        gbc.fill = GridBagConstraints.HORIZONTAL
        gbc.weightx = 1.0
        self.rag_lambda_field = JTextField("0.7")
        config_panel.add(self.rag_lambda_field, gbc)
        
        # RAG Document Count
        gbc.gridx = 0
        gbc.gridy = 6
        gbc.fill = GridBagConstraints.NONE
        gbc.weightx = 0.0
        config_panel.add(JLabel("RAG Documents (number to retrieve):"), gbc)
        
        gbc.gridx = 1
        gbc.fill = GridBagConstraints.HORIZONTAL
        gbc.weightx = 1.0
        self.rag_k_field = JTextField("5")
        config_panel.add(self.rag_k_field, gbc)
        
        panel.add(config_panel, BorderLayout.NORTH)
        
        # Add input query panel
        input_panel = JPanel(BorderLayout())
        input_panel.setBorder(BorderFactory.createTitledBorder("Target Query/Mutation to Test"))
        
        self.target_query_text = JTextArea(8, 50)
        self.target_query_text.setLineWrap(True)
        self.target_query_text.setText("# Paste the GraphQL query/mutation you want to test here\n# Example:\n# query getUser($id: ID!) {\n#   user(id: $id) {\n#     id\n#     name\n#     email\n#   }\n# }")
        target_scroll = JScrollPane(self.target_query_text)
        input_panel.add(target_scroll, BorderLayout.CENTER)
        
        # Add custom message panel
        custom_message_panel = JPanel(BorderLayout())
        custom_message_panel.setBorder(BorderFactory.createTitledBorder("Custom Message to LLM (Optional)"))
        
        self.custom_message_text = JTextArea(6, 50)
        self.custom_message_text.setLineWrap(True)
        self.custom_message_text.setText("# Optional: Send a custom message to the LLM\n# Example: \"Focus on testing for NoSQL injection vulnerabilities\"\n# Example: \"Generate variants that test for specific field access bypasses\"\n# Example: \"Create queries that test rate limiting and resource exhaustion\"")
        custom_message_scroll = JScrollPane(self.custom_message_text)
        custom_message_panel.add(custom_message_scroll, BorderLayout.CENTER)
        
        custom_button_panel = JPanel()
        self.send_custom_btn = JButton("Send Custom Message", actionPerformed=self.sendCustomMessage)
        custom_button_panel.add(self.send_custom_btn)
        custom_message_panel.add(custom_button_panel, BorderLayout.SOUTH)
        
        # Create a new split pane with four sections
        top_split = JSplitPane(JSplitPane.VERTICAL_SPLIT)
        top_split.setTopComponent(input_panel)
        top_split.setBottomComponent(custom_message_panel)
        top_split.setDividerLocation(200)
        
        main_split = JSplitPane(JSplitPane.VERTICAL_SPLIT)
        main_split.setTopComponent(top_split)
        
        split_pane = JSplitPane(JSplitPane.VERTICAL_SPLIT)
        
        queries_panel = JPanel(BorderLayout())
        queries_panel.setBorder(BorderFactory.createTitledBorder("Generated Malicious Variants"))
        
        self.queries_text = JTextArea(15, 50)
        self.queries_text.setLineWrap(True)
        queries_scroll = JScrollPane(self.queries_text)
        queries_panel.add(queries_scroll, BorderLayout.CENTER)
        
        gen_button_panel = JPanel()
        self.generate_btn = JButton("Generate Malicious Variants", actionPerformed=self.generateQueries)
        self.test_queries_btn = JButton("Test Queries", actionPerformed=self.testQueries)
        gen_button_panel.add(self.generate_btn)
        gen_button_panel.add(self.test_queries_btn)
        queries_panel.add(gen_button_panel, BorderLayout.SOUTH)
        
        split_pane.setTopComponent(queries_panel)
        
        results_panel = JPanel(BorderLayout())
        results_panel.setBorder(BorderFactory.createTitledBorder("Query Results"))
        
        self.results_text = JTextArea(8, 50)
        self.results_text.setLineWrap(True)
        results_scroll = JScrollPane(self.results_text)
        results_panel.add(results_scroll, BorderLayout.CENTER)
        
        split_pane.setBottomComponent(results_panel)
        split_pane.setDividerLocation(300)
        
        main_split.setBottomComponent(split_pane)
        main_split.setDividerLocation(380)
        
        panel.add(main_split, BorderLayout.CENTER)
        
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
        
        llm_endpoint = self.llm_endpoint_field.getText().strip()
        model_name = self.model_name_field.getText().strip()
        api_key = self.api_key_field.getText().strip()
        test_types = self.test_type_field.getText().strip()
        target_query = self.target_query_text.getText().strip()
        rag_endpoint = self.rag_endpoint_field.getText().strip()
        
        # Get RAG lambda multiplier for relevance/diversity balance
        rag_lambda = 0.7  # default value
        try:
            rag_lambda_text = self.rag_lambda_field.getText().strip()
            if rag_lambda_text:
                rag_lambda = float(rag_lambda_text)
                # Clamp to valid range
                rag_lambda = max(0.0, min(1.0, rag_lambda))
        except:
            rag_lambda = 0.7  # fallback to default
        
        # Get RAG document count
        rag_k = 5  # default value
        try:
            rag_k_text = self.rag_k_field.getText().strip()
            if rag_k_text:
                rag_k = int(rag_k_text)
                # Clamp to reasonable range
                rag_k = max(1, min(20, rag_k))
        except:
            rag_k = 5  # fallback to default
        
        print("[DEBUG] RAG lambda multiplier: " + str(rag_lambda))
        print("[DEBUG] RAG document count: " + str(rag_k))
        
        if not llm_endpoint:
            JOptionPane.showMessageDialog(self.main_panel, "Please enter your local LLM endpoint URL")
            return
            
        if not model_name:
            JOptionPane.showMessageDialog(self.main_panel, "Please enter your model name")
            return
            
        # Support both targeted and bulk generation modes
        if not target_query or target_query.startswith("#"):
            # Bulk generation mode - generate multiple security tests without specific target
            if not self._shutdown:
                self._executor.submit(self._createBulkGenerationRunnable(llm_endpoint, model_name, api_key, test_types, rag_endpoint, rag_lambda, rag_k))
            return
        
        # Use managed thread executor
        if not self._shutdown:
            self._executor.submit(self._createQueryGenerationRunnable(llm_endpoint, model_name, api_key, test_types, target_query, rag_endpoint, rag_lambda, rag_k))

    def _createQueryGenerationRunnable(self, llm_endpoint, model_name, api_key, test_types, target_query, rag_endpoint, rag_lambda, rag_k):
        """Create a runnable for query generation"""
        class QueryGenerationRunnable(Runnable):
            def __init__(self, extender, llm_endpoint, model_name, api_key, test_types, target_query, rag_endpoint, rag_lambda, rag_k):
                self.extender = extender
                self.llm_endpoint = llm_endpoint
                self.model_name = model_name
                self.api_key = api_key
                self.test_types = test_types
                self.target_query = target_query
                self.rag_endpoint = rag_endpoint
                self.rag_lambda = rag_lambda
                self.rag_k = rag_k
            
            def run(self):
                if self.extender._shutdown:
                    return
                try:
                    queries = self.extender.query_generator.generate_malicious_variants(self.extender.parsed_schema, self.llm_endpoint, self.model_name, self.api_key, self.test_types, self.target_query, self.rag_endpoint, self.rag_lambda, self.rag_k)
                    SwingUtilities.invokeLater(lambda: self.extender.queries_text.setText('\n'.join(queries)))
                except Exception as e:
                            SwingUtilities.invokeLater(lambda: JOptionPane.showMessageDialog(self.extender.main_panel, "Query generation failed: " + str(e)))
        
        return QueryGenerationRunnable(self, llm_endpoint, model_name, api_key, test_types, target_query, rag_endpoint, rag_lambda, rag_k)

    def _createBulkGenerationRunnable(self, llm_endpoint, model_name, api_key, test_types, rag_endpoint, rag_lambda, rag_k):
        """Create a runnable for bulk query generation"""
        class BulkGenerationRunnable(Runnable):
            def __init__(self, extender, llm_endpoint, model_name, api_key, test_types, rag_endpoint, rag_lambda, rag_k):
                self.extender = extender
                self.llm_endpoint = llm_endpoint
                self.model_name = model_name
                self.api_key = api_key
                self.test_types = test_types
                self.rag_endpoint = rag_endpoint
                self.rag_lambda = rag_lambda
                self.rag_k = rag_k
            
            def run(self):
                if self.extender._shutdown:
                    return
                try:
                    queries = self.extender.query_generator.generate_bulk_queries(self.extender.parsed_schema, self.llm_endpoint, self.model_name, self.api_key, self.test_types)
                    SwingUtilities.invokeLater(lambda: self.extender.queries_text.setText('\n'.join(queries)))
                except Exception as e:
                    SwingUtilities.invokeLater(lambda: JOptionPane.showMessageDialog(self.extender.main_panel, "Bulk query generation failed: " + str(e)))
        
        return BulkGenerationRunnable(self, llm_endpoint, model_name, api_key, test_types, rag_endpoint, rag_lambda, rag_k)

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

    def sendCustomMessage(self, event):
        """Send a custom message to the LLM"""
        # Prevent multiple simultaneous custom message calls
        if hasattr(self, '_custom_message_in_progress') and self._custom_message_in_progress:
            print("[DEBUG] Custom message already in progress, ignoring duplicate request")
            return
        
        custom_message = self.custom_message_text.getText().strip()
        llm_endpoint = self.llm_endpoint_field.getText().strip()
        model_name = self.model_name_field.getText().strip()
        api_key = self.api_key_field.getText().strip()
        rag_endpoint = self.rag_endpoint_field.getText().strip()
        
        # Get RAG lambda multiplier for relevance/diversity balance
        rag_lambda = 0.7  # default value
        try:
            rag_lambda_text = self.rag_lambda_field.getText().strip()
            if rag_lambda_text:
                rag_lambda = float(rag_lambda_text)
                # Clamp to valid range
                rag_lambda = max(0.0, min(1.0, rag_lambda))
        except:
            rag_lambda = 0.7  # fallback to default
        
        # Get RAG document count
        rag_k = 5  # default value
        try:
            rag_k_text = self.rag_k_field.getText().strip()
            if rag_k_text:
                rag_k = int(rag_k_text)
                # Clamp to reasonable range
                rag_k = max(1, min(20, rag_k))
        except:
            rag_k = 5  # fallback to default
        
        if not custom_message or custom_message.startswith("#"):
            JOptionPane.showMessageDialog(self.main_panel, "Please enter a custom message to send to the LLM")
            return
        
        self._custom_message_in_progress = True
        print("[DEBUG] Starting custom message processing with message: " + custom_message[:100] + "...")
        print("[DEBUG] RAG lambda multiplier: " + str(rag_lambda))
            
        if not llm_endpoint:
            self._custom_message_in_progress = False
            JOptionPane.showMessageDialog(self.main_panel, "Please enter your LLM endpoint URL")
            return
            
        if not model_name:
            self._custom_message_in_progress = False
            JOptionPane.showMessageDialog(self.main_panel, "Please enter your model name")
            return
        
        # Include schema context if available
        schema_context = ""
        if hasattr(self, 'parsed_schema'):
            schema_summary = self.query_generator._summarize_schema(self.parsed_schema)
            schema_context = "\n\nGRAPHQL SCHEMA CONTEXT:\n" + schema_summary[:1000] + ("..." if len(schema_summary) > 1000 else "")
        
        # Include external RAG context if available
        rag_context = ""
        if rag_endpoint:
            try:
                # Query external RAG for additional context
                external_knowledge = self.query_generator.query_external_rag(rag_endpoint, custom_message, k=rag_k, lambda_mult=rag_lambda)
                if external_knowledge:
                    rag_context = "\n\nEXTERNAL SECURITY KNOWLEDGE:\n"
                    for i, doc in enumerate(external_knowledge):
                        rag_context += "Document " + str(i+1) + ":\n" + doc['content'][:500] + "...\n\n"
            except Exception as e:
                print("[DEBUG] Failed to query external RAG for custom message: " + str(e))
        
        # Build the complete prompt
        full_prompt = custom_message + schema_context + rag_context
        
        # Use managed thread executor
        if not self._shutdown:
            self._executor.submit(self._createCustomMessageRunnable(llm_endpoint, model_name, api_key, full_prompt))
    
    def _createCustomMessageRunnable(self, llm_endpoint, model_name, api_key, message):
        """Create a runnable for custom message sending"""
        class CustomMessageRunnable(Runnable):
            def __init__(self, extender, llm_endpoint, model_name, api_key, message):
                self.extender = extender
                self.llm_endpoint = llm_endpoint
                self.model_name = model_name
                self.api_key = api_key
                self.message = message
            
            def run(self):
                if self.extender._shutdown:
                    return
                try:
                    # Create payload for custom message
                    payload = {
                        "model": self.model_name,
                        "messages": [{"role": "user", "content": self.message}],
                        "max_tokens": 2000,
                        "temperature": 0.7,
                        "stream": False
                    }
                    
                    # Execute API call
                    result = self.extender.query_generator._execute_llm_request(
                        self.llm_endpoint, self.model_name, self.api_key, payload)
                    
                    content = result['choices'][0]['message']['content']
                    print("[DEBUG] Custom message response length: " + str(len(content)))
                    
                    # For custom messages, just display the raw response without extraction
                    # since custom messages may not contain structured GraphQL queries
                    display_content = content
                    print("[DEBUG] Custom message response will be displayed as-is")
                    
                    SwingUtilities.invokeLater(lambda: self.extender.queries_text.setText(display_content))
                    print("[DEBUG] Custom message processing completed successfully")
                    
                except Exception as e:
                    SwingUtilities.invokeLater(lambda: JOptionPane.showMessageDialog(
                        self.extender.main_panel, "Custom message failed: " + str(e)))
                    print("[DEBUG] Custom message processing failed: " + str(e))
                finally:
                    # Reset the in-progress flag
                    self.extender._custom_message_in_progress = False
                    print("[DEBUG] Custom message processing flag reset")
        
        return CustomMessageRunnable(self, llm_endpoint, model_name, api_key, message)

    def getTabCaption(self):
        return "GraphQL Tester"

    def getUiComponent(self):
        return self.main_panel

    def processHttpMessage(self, toolFlag, messageIsRequest, messageInfo):
        pass
    
    def createMenuItems(self, invocation):
        menu_items = []
        
        # Only show menu for proxy requests/responses
        if invocation.getInvocationContext() in [IContextMenuInvocation.CONTEXT_PROXY_HISTORY, 
                                                IContextMenuInvocation.CONTEXT_TARGET_SITE_MAP_TABLE,
                                                IContextMenuInvocation.CONTEXT_TARGET_SITE_MAP_TREE]:
            
            # Get the selected HTTP message
            selected_messages = invocation.getSelectedMessages()
            
            if selected_messages:
                for message in selected_messages:
                    if self._isGraphQLRequest(message):
                        menu_item = JMenuItem("Load GraphQL query in Security Tester")
                        menu_item.addActionListener(lambda event, msg=message: self._loadGraphQLFromProxy(msg))
                        menu_items.append(menu_item)
                        break
        
        return menu_items
    
    def _isGraphQLRequest(self, message):
        try:
            request = message.getRequest()
            request_info = self._helpers.analyzeRequest(request)
            
            # Check if request contains GraphQL indicators
            request_str = self._helpers.bytesToString(request)
            
            # Look for GraphQL patterns
            if ('query' in request_str.lower() or 
                'mutation' in request_str.lower() or 
                'subscription' in request_str.lower() or
                'application/json' in request_str and 
                ('__schema' in request_str or '__type' in request_str)):
                return True
            
            # Check Content-Type for GraphQL
            headers = request_info.getHeaders()
            for header in headers:
                if header.lower().startswith('content-type:') and 'graphql' in header.lower():
                    return True
            
            return False
            
        except Exception as e:
            print("[DEBUG] Error checking GraphQL request: " + str(e))
            return False
    
    def _loadGraphQLFromProxy(self, message):
        try:
            # Extract GraphQL query from the request
            query = self._extractGraphQLQuery(message)
            
            if query:
                # Load the query into the schema text area
                SwingUtilities.invokeLater(lambda: self._loadQueryIntoTool(query, message))
            else:
                SwingUtilities.invokeLater(lambda: JOptionPane.showMessageDialog(
                    self.main_panel, 
                    "Could not extract GraphQL query from this request",
                    "Extraction Failed",
                    JOptionPane.WARNING_MESSAGE
                ))
                
        except Exception as e:
            SwingUtilities.invokeLater(lambda: JOptionPane.showMessageDialog(
                self.main_panel,
                "Error loading GraphQL query: " + str(e),
                "Error",
                JOptionPane.ERROR_MESSAGE
            ))
    
    def _extractGraphQLQuery(self, message):
        try:
            request = message.getRequest()
            request_info = self._helpers.analyzeRequest(request)
            
            # Get request body - return the whole body instead of parsing
            body_offset = request_info.getBodyOffset()
            request_body = request[body_offset:]
            body_str = self._helpers.bytesToString(request_body)
            
            # Return the entire request body to preserve JSON structure
            if body_str.strip():
                return body_str.strip()
            
            return None
            
        except Exception as e:
            print("[DEBUG] Error extracting GraphQL query: " + str(e))
            return None
    
    def _loadQueryIntoTool(self, query, message):
        try:
            # Also extract endpoint URL from the request
            request = message.getRequest()
            http_service = message.getHttpService()
            
            # Use the overloaded analyzeRequest method with HTTP service details
            request_info = self._helpers.analyzeRequest(http_service, request)
            
            # Build the full URL
            protocol = "https" if http_service.getPort() == 443 else "http"
            host = http_service.getHost()
            port = http_service.getPort()
            path = request_info.getUrl().getPath()
            
            if port not in [80, 443]:
                endpoint_url = "{0}://{1}:{2}{3}".format(protocol, host, port, path)
            else:
                endpoint_url = "{0}://{1}{2}".format(protocol, host, path)
            
            # Set the endpoint in the schema tab
            self.endpoint_field.setText(endpoint_url)
            
            # Create a formatted display of the extracted query
            formatted_content = "// Extracted from proxy request\n"
            formatted_content += "// URL: {0}\n\n".format(endpoint_url)
            formatted_content += query
            
            # Put the query in the schema text area as a starting point
            # User can then introspect to get the full schema
            self.schema_text.setText(formatted_content)
            
            # Extract just the GraphQL query/mutation part from the request body
            try:
                import json
                json_data = json.loads(query)
                if isinstance(json_data, dict) and 'query' in json_data:
                    clean_query = json_data['query']
                else:
                    clean_query = query
            except:
                clean_query = query
            
            # Put the clean query in the target query field for variant generation
            self.target_query_text.setText(clean_query)
            
            # Clear the generated queries area - user will generate variants from the target
            self.queries_text.setText("# Click 'Generate Malicious Variants' to create test cases for the loaded query")
            
            # Show success message
            JOptionPane.showMessageDialog(
                self.main_panel,
                "GraphQL query loaded successfully!\n\nEndpoint: {0}\n\nQuery has been loaded in both Schema and Query Generator tabs.".format(endpoint_url),
                "Query Loaded",
                JOptionPane.INFORMATION_MESSAGE
            )
            
        except Exception as e:
            print("[DEBUG] Error loading query into tool: " + str(e))
            JOptionPane.showMessageDialog(
                self.main_panel,
                "Error loading query: " + str(e),
                "Error",
                JOptionPane.ERROR_MESSAGE
            )
    
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


class RAGVectorDB:
    def __init__(self, faiss_store_path="/Users/nayan/Documents/Code/RAG_Generator/faiss_store"):
        self.faiss_store_path = faiss_store_path
        self.vectorstore = None
        self.embeddings = None
        self.rag_available = False
        self._initialize_rag()
    
    def _initialize_rag(self):
        """Initialize the RAG vector database"""
        try:
            # Check if we're in a Jython environment
            import sys
            is_jython = "java" in sys.platform.lower() or hasattr(sys, 'getJythonVersion')
            
            if is_jython:
                print("[RAG] Running in Jython environment - RAG features require CPython")
                print("[RAG] RAG integration disabled - will use built-in security knowledge")
                self.rag_available = False
                self.index = None
                self.metadata = None
                return
            
            # Try to import required libraries
            import faiss
            import pickle
            import os
            
            # Try to import sentence transformers - this might fail in restricted environments
            try:
                from sentence_transformers import SentenceTransformer
                self.embeddings = SentenceTransformer('all-MiniLM-L6-v2')
            except ImportError:
                print("[RAG] sentence-transformers not available - using simpler approach")
                self.embeddings = None
            
            # Load FAISS index and metadata
            index_path = os.path.join(self.faiss_store_path, "index.faiss")
            metadata_path = os.path.join(self.faiss_store_path, "index.pkl")
            
            if os.path.exists(index_path) and os.path.exists(metadata_path):
                # Load FAISS index
                self.index = faiss.read_index(index_path)
                
                # Load metadata
                with open(metadata_path, 'rb') as f:
                    self.metadata = pickle.load(f)
                
                self.rag_available = True
                print("[RAG] Vector database initialized successfully")
            else:
                print("[RAG] Warning: FAISS store not found at " + self.faiss_store_path)
                self.rag_available = False
                self.index = None
                self.metadata = None
                
        except ImportError as e:
            print("[RAG] RAG libraries not available: " + str(e))
            print("[RAG] Install faiss-cpu and sentence-transformers in your Python environment for RAG support")
            print("[RAG] Continuing without RAG - will use built-in security knowledge")
            self.rag_available = False
            self.index = None
            self.metadata = None
        except Exception as e:
            print("[RAG] Error initializing RAG: " + str(e))
            self.rag_available = False
            self.index = None
            self.metadata = None
    
    def query_rag(self, query_text, k=3):
        """Query the RAG vector database for relevant context"""
        if not self.rag_available or not self.index or not self.metadata or not self.embeddings:
            return self._get_fallback_security_knowledge(query_text)
        
        try:
            # Generate embedding for query
            query_embedding = self.embeddings.encode([query_text])
            
            # Search FAISS index
            distances, indices = self.index.search(query_embedding, k)
            
            # Retrieve relevant documents
            relevant_docs = []
            for i, idx in enumerate(indices[0]):
                if idx < len(self.metadata):
                    doc_content = self.metadata[idx].get('page_content', '')
                    doc_metadata = self.metadata[idx].get('metadata', {})
                    score = distances[0][i]
                    
                    relevant_docs.append({
                        'content': doc_content,
                        'metadata': doc_metadata,
                        'score': float(score)
                    })
            
            return relevant_docs
            
        except Exception as e:
            print("[RAG] Error querying RAG: " + str(e))
            return self._get_fallback_security_knowledge(query_text)
    
    def get_security_context(self, vulnerability_types):
        """Get security-specific context from RAG for given vulnerability types"""
        if not self.rag_available:
            return self._get_fallback_security_knowledge_for_types(vulnerability_types)
        
        context_docs = []
        
        for vuln_type in vulnerability_types:
            # Query for each vulnerability type
            query = "GraphQL security " + vuln_type + " vulnerability testing"
            docs = self.query_rag(query, k=2)
            context_docs.extend(docs)
        
        # Deduplicate and return top results
        seen_content = set()
        unique_docs = []
        for doc in context_docs:
            if doc['content'] not in seen_content:
                seen_content.add(doc['content'])
                unique_docs.append(doc)
        
        return unique_docs[:5]  # Return top 5 unique documents
    
    def _get_fallback_security_knowledge(self, query_text):
        """Provide built-in security knowledge when RAG is not available"""
        fallback_docs = []
        
        query_lower = query_text.lower()
        
        if "sql injection" in query_lower or "injection" in query_lower:
            fallback_docs.append({
                'content': """GraphQL SQL Injection Testing:
- Test string/ID parameters with SQL injection payloads like ' OR '1'='1
- Try time-based injection payloads: ' OR SLEEP(5)--
- Test for NoSQL injection: {"$ne": null}
- Use GraphQL variables to inject malicious SQL
- Target resolver functions that construct SQL queries""",
                'metadata': {'source': 'built-in'},
                'score': 0.9
            })
        
        if "authorization" in query_lower or "bypass" in query_lower:
            fallback_docs.append({
                'content': """GraphQL Authorization Bypass Testing:
- Modify user IDs to access other users' data
- Test field-level authorization by requesting restricted fields
- Try accessing admin-only mutations with regular user tokens
- Test for horizontal privilege escalation
- Check if authentication tokens are properly validated""",
                'metadata': {'source': 'built-in'},
                'score': 0.9
            })
        
        if "dos" in query_lower or "denial" in query_lower:
            fallback_docs.append({
                'content': """GraphQL DoS Attack Testing:
- Create deeply nested queries to exhaust server resources
- Request large result sets to consume memory
- Use query complexity attacks with expensive operations
- Test for algorithmic complexity attacks
- Try resource exhaustion through recursive queries""",
                'metadata': {'source': 'built-in'},
                'score': 0.9
            })
        
        return fallback_docs
    
    def _get_fallback_security_knowledge_for_types(self, vulnerability_types):
        """Get built-in security knowledge for specific vulnerability types"""
        all_docs = []
        
        for vuln_type in vulnerability_types:
            docs = self._get_fallback_security_knowledge("GraphQL " + vuln_type + " testing")
            all_docs.extend(docs)
        
        return all_docs


class GPTQueryGenerator:
    def __init__(self, callbacks, helpers):
        self.callbacks = callbacks
        self.helpers = helpers
        
        # Initialize RAG vector database
        self.rag_db = RAGVectorDB()
        
        # Offline fallback queries for common GraphQL patterns
        self._fallback_queries = [
            "query { __schema { types { name } } }",
            "query { __type(name: \"Query\") { fields { name } } }",
            "mutation { __typename }",
            "query { user(id: \"1' OR '1'='1\") { id name email } }",
            "query { users(limit: 999999) { id name email password } }"
        ]

    def query_external_rag(self, rag_endpoint, query_text, k=5, lambda_mult=0.7):
        """Query external RAG service for GraphQL security knowledge"""
        if not rag_endpoint or not rag_endpoint.strip():
            print("[DEBUG] No external RAG endpoint configured")
            return []
        
        # Prevent duplicate RAG queries with the same text and parameters
        rag_cache_key = "rag_" + str(hash(query_text[:100] + str(k) + str(lambda_mult)))
        if hasattr(self, '_rag_query_cache') and rag_cache_key in self._rag_query_cache:
            print("[DEBUG] Using cached RAG result for duplicate query (k=" + str(k) + ", lambda=" + str(lambda_mult) + ")")
            return self._rag_query_cache[rag_cache_key]
        
        try:
            print("[DEBUG] Querying external RAG at: " + rag_endpoint)
            print("[DEBUG] RAG query: " + query_text[:100] + "...")
            
            from java.net import URL
            print("[DEBUG] Java URL import successful")
            
            # Parse RAG endpoint URL and add the correct path
            if not rag_endpoint.endswith('/similarity_search'):
                if rag_endpoint.endswith('/'):
                    full_url = rag_endpoint + "similarity_search"
                else:
                    full_url = rag_endpoint + "/similarity_search"
            else:
                full_url = rag_endpoint
            
            url = URL(full_url)
            host = url.getHost()
            port = url.getPort() if url.getPort() != -1 else (443 if url.getProtocol() == 'https' else 80)
            use_https = url.getProtocol() == 'https'
            
            # Create HTTP service
            http_service = self.helpers.buildHttpService(host, port, use_https)
            
            # Prepare RAG query payload using the enhanced API format with MMR search
            rag_payload = {
                "query": query_text,
                "k": k,
                "search_type": "mmr",          # Use MMR for diverse document selection
                "fetch_k": k * 3,              # Fetch more candidates for MMR selection
                "lambda_mult": lambda_mult     # Configurable relevance/diversity balance
            }
            
            data = json.dumps(rag_payload)
            
            # Extract path from URL
            path = url.getPath()
            if not path:
                path = "/similarity_search"
            
            # Build HTTP request
            headers = [
                "POST " + path + " HTTP/1.1",
                "Host: " + host,
                "Content-Type: application/json",
                "User-Agent: GraphQL-Security-Tester/1.0",
                "Content-Length: " + str(len(data.encode('utf-8'))),
                "",
                data
            ]
            
            request_str = "\r\n".join(headers)
            request = self.helpers.stringToBytes(request_str)
            
            print("[DEBUG] RAG request details:")
            print("[DEBUG] Host: " + host + ", Port: " + str(port) + ", HTTPS: " + str(use_https))
            print("[DEBUG] Full URL: " + full_url)
            print("[DEBUG] Path: " + path)
            print("[DEBUG] Payload: " + data)
            print("[DEBUG] Request headers: " + str(headers[:4]))  # Don't print the data part
            
            # Make the request
            print("[DEBUG] Making HTTP request to RAG server...")
            response = self.callbacks.makeHttpRequest(http_service, request)
            print("[DEBUG] RAG request completed, analyzing response...")
            response_info = self.helpers.analyzeResponse(response.getResponse())
            status_code = response_info.getStatusCode()
            print("[DEBUG] RAG response status code: " + str(status_code))
            
            if status_code == 200:
                response_body = response.getResponse()[response_info.getBodyOffset():]
                response_str = self.helpers.bytesToString(response_body)
                
                try:
                    rag_result = json.loads(response_str)
                    print("[DEBUG] External RAG response received, processing results...")
                    
                    # Process RAG results based on your API's response format
                    knowledge_docs = []
                    
                    if isinstance(rag_result, dict) and 'results' in rag_result:
                        results = rag_result['results']
                        print("[DEBUG] Found " + str(len(results)) + " results from external RAG")
                        
                        for i, result in enumerate(results[:k]):
                            # Your RAG API returns documents with specific structure
                            if isinstance(result, dict):
                                # Extract content and metadata from your RAG response format
                                content = result.get('page_content', '') or result.get('content', '') or result.get('text', '')
                                metadata = result.get('metadata', {})
                                
                                # Handle Unicode characters in content (works in both Python 2/Jython and Python 3)
                                if content:
                                    try:
                                        # Check if this is a Unicode string (Jython/Python 2)
                                        if hasattr(content, 'encode') and (isinstance(content, unicode) if 'unicode' in dir(__builtins__) else False):
                                            # Clean up problematic Unicode characters
                                            content = content.replace(u'\xa0', u' ')  # Replace non-breaking space
                                            content = content.replace(u'\u2019', u"'")  # Replace smart quote
                                            content = content.replace(u'\u201c', u'"')  # Replace smart quote
                                            content = content.replace(u'\u201d', u'"')  # Replace smart quote
                                            content = content.replace(u'\u2013', u'-')  # Replace en dash
                                            content = content.replace(u'\u2014', u'-')  # Replace em dash
                                            # Encode to ASCII with replacement for any remaining problematic characters
                                            content = content.encode('ascii', 'replace').decode('ascii')
                                        elif isinstance(content, str):
                                            # Handle regular string content - clean up common problematic chars
                                            content = content.replace('\xa0', ' ')  # Replace non-breaking space
                                            content = content.replace('\u2019', "'")  # Replace smart quote
                                            content = content.replace('\u201c', '"')  # Replace smart quote
                                            content = content.replace('\u201d', '"')  # Replace smart quote
                                            content = content.replace('\u2013', '-')  # Replace en dash
                                            content = content.replace('\u2014', '-')  # Replace em dash
                                    except Exception as e:
                                        print("[DEBUG] Error cleaning external RAG Unicode content: " + str(e))
                                        # If Unicode handling fails, try to encode as ASCII with replacement
                                        try:
                                            if hasattr(content, 'encode'):
                                                content = content.encode('ascii', 'replace')
                                                if hasattr(content, 'decode'):
                                                    content = content.decode('ascii')
                                        except:
                                            pass  # Use content as-is if all else fails
                                
                                # Extract source information
                                source = metadata.get('source', 'external_rag')
                                if 'file_path' in metadata:
                                    source = metadata['file_path']
                                
                                if content:
                                    knowledge_docs.append({
                                        'content': content,
                                        'metadata': {
                                            'source': 'external_rag',
                                            'file_source': source,
                                            'original_metadata': metadata
                                        },
                                        'score': 0.8  # Default score for external RAG results
                                    })
                            else:
                                # Fallback for simple string results
                                knowledge_docs.append({
                                    'content': str(result),
                                    'metadata': {'source': 'external_rag'},
                                    'score': 0.5
                                })
                    else:
                        print("[DEBUG] Unexpected response format from external RAG")
                        return []
                    
                    print("[DEBUG] Processed " + str(len(knowledge_docs)) + " knowledge documents from external RAG")
                    
                    # Cache the result to prevent duplicate queries
                    if not hasattr(self, '_rag_query_cache'):
                        self._rag_query_cache = {}
                    self._rag_query_cache[rag_cache_key] = knowledge_docs
                    
                    return knowledge_docs
                    
                except Exception as e:
                    print("[DEBUG] Error parsing RAG response: " + str(e))
                    print("[DEBUG] Raw response: " + response_str[:500] + "...")
                    return []
            else:
                print("[DEBUG] External RAG request failed with status: " + str(status_code))
                return []
                
        except Exception as e:
            print("[DEBUG] Error querying external RAG with Burp HTTP: " + str(e))
            print("[DEBUG] Trying alternative HTTP approach...")
            # Try alternative approach using Python urllib
            try:
                import urllib2
                import json
                
                # Prepare the request using enhanced API format with MMR search
                rag_payload = {
                    "query": query_text,
                    "k": k,
                    "search_type": "mmr",          # Use MMR for diverse document selection
                    "fetch_k": k * 3,              # Fetch more candidates for MMR selection
                    "lambda_mult": lambda_mult     # Configurable relevance/diversity balance
                }
                
                data = json.dumps(rag_payload)
                
                # Construct the full URL
                if not rag_endpoint.endswith('/similarity_search'):
                    if rag_endpoint.endswith('/'):
                        full_url = rag_endpoint + "similarity_search"
                    else:
                        full_url = rag_endpoint + "/similarity_search"
                else:
                    full_url = rag_endpoint
                
                print("[DEBUG] Alternative approach using URL: " + full_url)
                print("[DEBUG] Alternative approach payload: " + data)
                
                # Create the request
                req = urllib2.Request(full_url, data, {'Content-Type': 'application/json'})
                response = urllib2.urlopen(req, timeout=10)
                response_data = response.read()
                
                print("[DEBUG] Alternative approach got response, length: " + str(len(response_data)))
                
                # Parse the response
                rag_result = json.loads(response_data)
                knowledge_docs = []
                
                if isinstance(rag_result, dict) and 'results' in rag_result:
                    results = rag_result['results']
                    print("[DEBUG] Alternative approach found " + str(len(results)) + " results")
                    
                    for result in results[:k]:
                        if isinstance(result, dict):
                            content = result.get('content', '')
                            metadata = result.get('metadata', {})
                            
                            if content:
                                # Clean Unicode characters
                                try:
                                    content = content.replace('\xa0', ' ')
                                    content = content.replace('\u2019', "'")
                                    content = content.replace('\u201c', '"')
                                    content = content.replace('\u201d', '"')
                                    content = content.replace('\u2013', '-')
                                    content = content.replace('\u2014', '-')
                                except:
                                    pass
                                
                                knowledge_docs.append({
                                    'content': content,
                                    'metadata': {
                                        'source': 'external_rag',
                                        'file_source': metadata.get('source', 'external_rag'),
                                        'original_metadata': metadata
                                    },
                                    'score': 0.8
                                })
                
                print("[DEBUG] Alternative approach processed " + str(len(knowledge_docs)) + " documents")
                
                # Cache the result
                if not hasattr(self, '_rag_query_cache'):
                    self._rag_query_cache = {}
                self._rag_query_cache[rag_cache_key] = knowledge_docs
                
                return knowledge_docs
                
            except Exception as e2:
                print("[DEBUG] Alternative approach also failed: " + str(e2))
                # Cache empty result to prevent retries
                if not hasattr(self, '_rag_query_cache'):
                    self._rag_query_cache = {}
                self._rag_query_cache[rag_cache_key] = []
                return []

    def _build_enhanced_security_context(self, vulnerability_types, rag_endpoint, lambda_mult=0.7, rag_k=5):
        """Build enhanced security context combining internal and external RAG"""
        all_knowledge = []
        
        # Get internal RAG knowledge (existing functionality)
        try:
            internal_knowledge = self.rag_db.get_security_context(vulnerability_types)
            if internal_knowledge:
                all_knowledge.extend(internal_knowledge)
                print("[DEBUG] Added " + str(len(internal_knowledge)) + " internal RAG documents")
        except Exception as e:
            print("[DEBUG] Internal RAG failed: " + str(e))
        
        # Get external RAG knowledge (new functionality)
        if rag_endpoint and rag_endpoint.strip():
            query_text = "GraphQL security vulnerabilities " + " ".join(vulnerability_types)
            external_knowledge = self.query_external_rag(rag_endpoint, query_text, k=rag_k, lambda_mult=lambda_mult)
            if external_knowledge:
                all_knowledge.extend(external_knowledge)
                print("[DEBUG] Added " + str(len(external_knowledge)) + " external RAG documents")
        
        return all_knowledge
        
    def generate_malicious_variants(self, schema, llm_endpoint, model_name, api_key, test_types, target_query, rag_endpoint=None, lambda_mult=0.7, rag_k=5):
        """Generate malicious variants of a specific target query/mutation"""
        try:
            print("[DEBUG] Starting targeted variant generation...")
            print("[DEBUG] Test types: " + str(test_types))
            print("[DEBUG] Target query: " + target_query[:200] + "...")
            
            schema_summary = self._summarize_schema(schema)
            print("[DEBUG] Schema summary length: " + str(len(schema_summary)))
            
            # Get enhanced RAG context for security testing (internal + external)
            test_types_list = [t.strip() for t in test_types.split(",") if t.strip()]
            print("[DEBUG] Test types for RAG query: " + str(test_types_list))
            
            try:
                rag_context = self._build_enhanced_security_context(test_types_list, rag_endpoint, lambda_mult, rag_k)
                print("[DEBUG] Enhanced RAG query completed, results: " + str(len(rag_context) if rag_context else 0))
            except Exception as e:
                print("[DEBUG] Enhanced RAG query failed: " + str(e))
                rag_context = []
            
            # Build RAG context string with Unicode handling
            rag_context_str = ""
            if rag_context:
                print("[DEBUG] Retrieved " + str(len(rag_context)) + " total RAG documents")
                rag_context_str = "\n\nSECURITY KNOWLEDGE BASE:\n"
                for i, doc in enumerate(rag_context):
                    try:
                        source = doc.get('metadata', {}).get('source', 'unknown')
                        content = doc['content'][:500]
                        
                        # Handle Unicode characters properly (works in both Python 2/Jython and Python 3)
                        try:
                            # Check if this is a Unicode string (Jython/Python 2)
                            if hasattr(content, 'encode') and (isinstance(content, unicode) if 'unicode' in dir(__builtins__) else False):
                                # Clean up problematic Unicode characters
                                content = content.replace(u'\xa0', u' ')  # Replace non-breaking space
                                content = content.replace(u'\u2019', u"'")  # Replace smart quote
                                content = content.replace(u'\u201c', u'"')  # Replace smart quote
                                content = content.replace(u'\u201d', u'"')  # Replace smart quote
                                content = content.replace(u'\u2013', u'-')  # Replace en dash
                                content = content.replace(u'\u2014', u'-')  # Replace em dash
                                # Encode to ASCII with replacement for any remaining problematic characters
                                content = content.encode('ascii', 'replace').decode('ascii')
                            elif isinstance(content, str):
                                # Handle regular string content - clean up common problematic chars
                                content = content.replace('\xa0', ' ')  # Replace non-breaking space
                                content = content.replace('\u2019', "'")  # Replace smart quote
                                content = content.replace('\u201c', '"')  # Replace smart quote
                                content = content.replace('\u201d', '"')  # Replace smart quote
                                content = content.replace('\u2013', '-')  # Replace en dash
                                content = content.replace('\u2014', '-')  # Replace em dash
                        except Exception as e:
                            print("[DEBUG] Error cleaning Unicode content: " + str(e))
                            # If Unicode handling fails, try to encode as ASCII with replacement
                            try:
                                if hasattr(content, 'encode'):
                                    content = content.encode('ascii', 'replace')
                                    if hasattr(content, 'decode'):
                                        content = content.decode('ascii')
                            except:
                                pass  # Use content as-is if all else fails
                        
                        rag_context_str += "Document " + str(i+1) + " (" + str(source) + "):\n" + content + "...\n\n"
                    except Exception as e:
                        print("[DEBUG] Error processing document " + str(i+1) + ": " + str(e))
                        # Skip problematic document
                        continue
            else:
                print("[DEBUG] No RAG context retrieved")
            
            prompt = """
You are a security researcher and penetration tester testing a specific GraphQL query/mutation. Based on the schema provided, the security knowledge base, and the target query below, generate malicious variants to test for each of the security vulnerabilities listed below.

SCHEMA:
{0}

TARGET QUERY/MUTATION TO TEST:
{1}
{2}
TASK: Create malicious variants of the target query above to test for:
- Authorization bypass (modify parameters to access restricted data)
- Data exfiltration (request additional sensitive fields that exist in schema)
- Input validation bypass (inject malicious payloads into variables/parameters)
- SQL injection attempts (modify string/ID parameters with injection payloads)
- Alias based attacks (use aliases to perform dos attacks)
- Denial of Service (deeply nested queries, large result sets)
- Cross Site Scripting (XSS) (inject script tags into string fields)
- Command Injection (inject OS commands into string fields)
- Log Injection (inject log commands into string fields)
- HTML Injection (inject HTML tags into string fields)
- Server Side Request Forgery (SSRF) (try to access internal services)
- Field Duplication attacks (duplicate fields to exhaust resources)


Use the security knowledge base above to inform your testing approaches and techniques.

REQUIREMENTS:
1. Use the EXACT structure of the target query as a base
2. Only use field names and types that exist in the provided schema
3. If the target query uses variables, create variants with malicious variable values
4. Keep the same operation type (query/mutation) as the target
5. Generate different malicious variants for each attack vector specified in Task
6. Each variant should test a different attack vector
7. Look at the schema and find the exact query/mutation that matches the target query structure and use it as a base for variants.
8. If the target query is a mutation, ensure the variants are also mutations with malicious inputs.
9. If the target query is a query, ensure the variants are also queries with malicious inputs.
10. Do not invent fields that do not exist in the schema.
11. Apply security testing techniques from the knowledge base where applicable.
12. Use the provided schema to construct malicious output. Only use fields and types that exist in the schema under that query/mutation.
13. Understand the structure of the target query and maintain it in the variants.
14. Always refer to the schema for valid field names and types.
15. Exact Structure Preservation: Use the exact field and argument structure of the target query/mutation.
16. Do not add or remove top-level fields unless the attack vector requires it (e.g., adding extra fields for data exfiltration).
17. Schema Validity: All fields, arguments, and types must exist in the provided schema.
18. Never invent names or types.
19. Variable Handling: If the target uses variables, keep variable names the same. 
20. Ensure all modified variables still match the declared GraphQL type (e.g., inject SQL payloads into strings, not ints).
21. If the query uses inline arguments instead of variables, place payloads directly into those arguments.
22. One Attack Vector per Variant: Generate one distinct variant for each vulnerability type listed above. Each variant must only target one vulnerability type.
23. Operation Type Consistency: If the target is a query, all variants must be queries. If the target is a mutation, all variants must be mutations.

Return only valid GraphQL queries that maintain the target query's structure while adding malicious elements.
""".format(schema_summary, target_query, rag_context_str)

            payload = {
                "model": model_name,
                "messages": [{"role": "user", "content": prompt}],
                "max_tokens": 1500,
                "temperature": 0.7,
                "stream": False
            }
            
            # Test connection first with a simple request
            if not hasattr(self, '_connection_tested'):
                self._connection_tested = self._test_llm_connection(llm_endpoint, model_name, api_key)
            
            # Execute API call with retry logic
            result = self._execute_llm_request(llm_endpoint, model_name, api_key, payload)
            
            content = result['choices'][0]['message']['content']
            print("[DEBUG] Received response from OpenAI, length: " + str(len(content)))
            
            # Use the centralized query extraction method with single-line conversion
            queries = self._extract_queries_from_response(content)
            
            return queries if queries else [content]
            
        except Exception as e:
            print("[DEBUG] Variant generation failed, using offline fallback: " + str(e))
            # Provide basic variants of the target query
            return self._get_offline_variants(target_query, schema, test_types)
    
    def generate_bulk_queries(self, schema, llm_endpoint, model_name, api_key, test_types):
        """Generate multiple security test queries for comprehensive testing"""
        try:
            print("[DEBUG] Starting bulk query generation...")
            print("[DEBUG] Test types: " + str(test_types))
            
            schema_summary = self._summarize_schema(schema)
            print("[DEBUG] Schema summary length: " + str(len(schema_summary)))
            
            # Get RAG context for security testing
            test_types_list = [t.strip() for t in test_types.split(",") if t.strip()]
            print("[DEBUG] Test types for RAG query: " + str(test_types_list))
            
            try:
                rag_context = self.rag_db.get_security_context(test_types_list)
                print("[DEBUG] RAG query completed, results: " + str(len(rag_context) if rag_context else 0))
            except Exception as e:
                print("[DEBUG] RAG query failed: " + str(e))
                rag_context = []
            
            # Build RAG context string
            rag_context_str = ""
            if rag_context:
                print("[DEBUG] Retrieved " + str(len(rag_context)) + " RAG documents")
                rag_context_str = "\n\nSECURITY KNOWLEDGE BASE:\n"
                for i, doc in enumerate(rag_context):
                    rag_context_str += "Document " + str(i+1) + ":\n" + doc['content'][:500] + "...\n\n"
            else:
                print("[DEBUG] No RAG context retrieved")
            
            prompt = """
You are a security researcher performing comprehensive GraphQL security testing. Based on the schema provided and the security knowledge base, generate multiple malicious GraphQL queries to test for various security vulnerabilities.

SCHEMA:
{0}
{1}
TASK: Generate comprehensive security test queries for:
- SQL injection (test string/ID parameters with injection payloads)
- Authorization bypass (attempt to access restricted fields/operations)
- Data exfiltration (request sensitive fields that shouldn't be accessible)
- Input validation bypass (inject malicious payloads into input fields)
- DoS attacks (deeply nested queries, large result sets)
- Information disclosure (introspection, error enumeration)
- Cross Site Scripting
- Command Injection
- HTML Injection
- Log Injection
- Alias based DoS
- Server Side Request Forgery 

Use the security knowledge base above to inform your testing approaches and techniques.

REQUIREMENTS:
1. Only use field names and types that exist in the provided schema
2. Generate 8-12 diverse test queries
3. Each query should test a different attack vector or vulnerability type
4. Include both queries and mutations where applicable
5. Use realistic field names and structures from the schema
6. Include introspection queries for schema discovery
7. Apply security testing techniques from the knowledge base where applicable
8. Ensure queries are syntactically valid GraphQL

Return only valid GraphQL queries, one per section separated by triple backticks.
""".format(schema_summary, rag_context_str)

            payload = {
                "model": model_name,
                "messages": [{"role": "user", "content": prompt}],
                "max_tokens": 2000,
                "temperature": 0.7,
                "stream": False
            }
            
            # Execute API call with retry logic
            result = self._execute_llm_request(llm_endpoint, model_name, api_key, payload)
            
            content = result['choices'][0]['message']['content']
            print("[DEBUG] Received bulk generation response, length: " + str(len(content)))
            
            # Extract queries from response
            queries = self._extract_queries_from_response(content)
            print("[DEBUG] Total bulk queries extracted: " + str(len(queries)))
            
            return queries if queries else self._get_offline_queries(schema, test_types)
            
        except Exception as e:
            print("[DEBUG] Bulk generation failed, using offline fallback: " + str(e))
            return self._get_offline_queries(schema, test_types)

    def _execute_llm_request(self, llm_endpoint, model_name, api_key, payload):
        """Execute LLM API request with retry logic"""
        data = json.dumps(payload)
        
        # Use Burp's HTTP service for LLM API calls
        from java.net import URL
        
        # Determine if this is OpenAI API or another endpoint
        if "openai.com" in llm_endpoint:
            url = URL("https://api.openai.com/v1/chat/completions")
            auth_header = "Authorization: Bearer " + api_key
        else:
            url = URL(llm_endpoint)
            auth_header = "Authorization: Bearer " + api_key if api_key else None
        
        host = url.getHost()
        port = url.getPort() if url.getPort() != -1 else (443 if url.getProtocol() == 'https' else 80)
        use_https = url.getProtocol() == 'https'
        
        # Create HTTP service
        http_service = self.helpers.buildHttpService(host, port, use_https)
        
        # Build request
        headers = [
            "Host: " + host,
            "Content-Type: application/json",
            "User-Agent: GraphQL-Security-Tester/1.0"
        ]
        
        if auth_header:
            headers.insert(2, auth_header)
        
        request = self.helpers.buildHttpMessage(headers, data.encode('utf-8'))
        
        # Retry logic
        max_retries = 3
        for attempt in range(max_retries):
            try:
                response = self.callbacks.makeHttpRequest(http_service, request)
                response_info = self.helpers.analyzeResponse(response.getResponse())
                status_code = response_info.getStatusCode()
                
                if status_code == 200:
                    response_body = response.getResponse()[response_info.getBodyOffset():]
                    response_str = self.helpers.bytesToString(response_body)
                    result = json.loads(response_str)
                    print("[DEBUG] API request successful")
                    return result
                elif status_code == 429 and attempt < max_retries - 1:
                    wait_time = (2 ** attempt) * 5
                    print("[DEBUG] Rate limited, waiting " + str(wait_time) + " seconds...")
                    time.sleep(wait_time)
                    continue
                else:
                    # Get error response body for debugging
                    error_body = ""
                    try:
                        if response_info.getBodyOffset() < len(response.getResponse()):
                            error_response_body = response.getResponse()[response_info.getBodyOffset():]
                            error_body = self.helpers.bytesToString(error_response_body)
                            print("[DEBUG] Error response body: " + error_body[:500])
                        else:
                            print("[DEBUG] No response body available")
                    except Exception as e:
                        print("[DEBUG] Could not read error response: " + str(e))
                    
                    # Get response headers for more debugging info
                    try:
                        headers_section = response.getResponse()[:response_info.getBodyOffset()]
                        headers_str = self.helpers.bytesToString(headers_section)
                        print("[DEBUG] Response headers: " + headers_str[:300])
                    except Exception as e:
                        print("[DEBUG] Could not read headers: " + str(e))
                    
                    raise Exception("HTTP " + str(status_code) + " error from LLM API. Response: " + error_body[:200])
                    
            except Exception as e:
                if attempt == max_retries - 1:
                    print("[DEBUG] All attempts failed: " + str(e))
                    raise e
                else:
                    print("[DEBUG] Attempt failed, retrying: " + str(e))
                    time.sleep(2)

    def _extract_queries_from_response(self, content):
        """Extract GraphQL queries from API response, preserve explanatory text, and convert queries to single-line format"""
        try:
            print("[DEBUG] _extract_queries_from_response called with content length: " + str(len(content)))
            
            # Clean Unicode characters and unescape JSON strings first to prevent encoding issues
            try:
                if hasattr(content, 'replace'):
                    # First, unescape JSON-encoded strings (common issue with LLM API responses)
                    content = content.replace('\\n', '\n')  # Convert \n to actual newlines
                    content = content.replace('\\t', '\t')  # Convert \t to actual tabs  
                    content = content.replace('\\"', '"')   # Convert \" to actual quotes
                    content = content.replace('\\\\', '\\') # Convert \\ to actual backslashes
                    
                    # Handle common Unicode characters that cause issues in Jython
                    content = content.replace(u'\u2013', u'-')  # en dash
                    content = content.replace(u'\u2014', u'-')  # em dash  
                    content = content.replace(u'\u2010', u'-')  # hyphen
                    content = content.replace(u'\u2011', u'-')  # non-breaking hyphen
                    content = content.replace(u'\u2019', u"'")  # right single quotation mark
                    content = content.replace(u'\u201c', u'"')  # left double quotation mark
                    content = content.replace(u'\u201d', u'"')  # right double quotation mark
                    content = content.replace(u'\xa0', u' ')    # non-breaking space
                    
                    # If still unicode, encode with replacement for any remaining problematic chars
                    if 'unicode' in str(type(content)):
                        content = content.encode('ascii', 'replace').decode('ascii')
                
                print("[DEBUG] Content preview after Unicode cleanup and JSON unescaping: " + content[:300] + "...")
            except Exception as e:
                print("[DEBUG] Unicode cleanup failed: " + str(e))
                try:
                    content = str(content).encode('ascii', 'replace').decode('ascii')
                except:
                    pass
            
            result_sections = []
            sections = content.split('```')
            print("[DEBUG] Found " + str(len(sections)) + " sections in response")
            
            i = 0
            while i < len(sections):
                section = sections[i].strip()
                
                # Clean Unicode in this section too
                try:
                    if hasattr(section, 'replace'):
                        section = section.replace(u'\u2013', u'-')  # en dash
                        section = section.replace(u'\u2014', u'-')  # em dash  
                        section = section.replace(u'\u2010', u'-')  # hyphen
                        section = section.replace(u'\u2011', u'-')  # non-breaking hyphen
                        section = section.replace(u'\u2019', u"'")  # right single quotation mark
                        section = section.replace(u'\u201c', u'"')  # left double quotation mark
                        section = section.replace(u'\u201d', u'"')  # right double quotation mark
                        section = section.replace(u'\xa0', u' ')    # non-breaking space
                        
                        if 'unicode' in str(type(section)):
                            section = section.encode('ascii', 'replace').decode('ascii')
                except:
                    pass
                
                try:
                    section_preview = section[:200]
                    print("[DEBUG] Processing section " + str(i) + " content: " + section_preview + "...")
                except:
                    print("[DEBUG] Processing section " + str(i) + " (content encoding issue)")
                
                # Check if this is explanatory text (even-numbered sections are usually text between code blocks)
                if i % 2 == 0 and section:
                    # This might be explanatory text - look ahead to see if next section is GraphQL
                    if i + 1 < len(sections):
                        next_section = sections[i + 1].strip()
                        
                        # Clean Unicode in next_section too
                        try:
                            if hasattr(next_section, 'replace'):
                                next_section = next_section.replace(u'\u2013', u'-')  # en dash
                                next_section = next_section.replace(u'\u2014', u'-')  # em dash  
                                next_section = next_section.replace(u'\u2010', u'-')  # hyphen
                                next_section = next_section.replace(u'\u2011', u'-')  # non-breaking hyphen
                                next_section = next_section.replace(u'\u2019', u"'")  # right single quotation mark
                                next_section = next_section.replace(u'\u201c', u'"')  # left double quotation mark
                                next_section = next_section.replace(u'\u201d', u'"')  # right double quotation mark
                                next_section = next_section.replace(u'\xa0', u' ')    # non-breaking space
                                
                                if 'unicode' in str(type(next_section)):
                                    next_section = next_section.encode('ascii', 'replace').decode('ascii')
                        except:
                            pass
                        
                        # Improved GraphQL detection - handle sections that start with "graphql"
                        is_graphql = self._is_graphql_section(next_section)
                        
                        try:
                            next_preview = next_section[:100]
                            print("[DEBUG] Looking ahead at section " + str(i+1) + ": " + next_preview + "...")
                        except:
                            print("[DEBUG] Looking ahead at section " + str(i+1) + " (encoding issue)")
                        
                        if is_graphql:
                            print("[DEBUG] Section " + str(i+1) + " contains GraphQL - combining with explanation")
                            
                            # Clean up GraphQL section - remove "graphql" language identifier
                            graphql_section = self._clean_graphql_section(next_section)
                            
                            # Convert GraphQL to single line
                            single_line_query = self._convert_to_single_line(graphql_section.strip())
                            
                            # Combine explanation with single-line query
                            combined_result = section + "\n" + single_line_query
                            result_sections.append(combined_result)
                            
                            try:
                                combined_preview = combined_result[:150].encode('utf-8', 'replace')
                                print("[DEBUG] Added combined section: " + combined_preview + "...")
                            except:
                                print("[DEBUG] Added combined section (encoding issue)")
                            
                            # Skip the next section since we processed it
                            i += 2
                            continue
                        else:
                            print("[DEBUG] Next section is not GraphQL, treating current section as standalone text")
                            if section:
                                result_sections.append(section)
                    else:
                        print("[DEBUG] No next section, adding current section as text")
                        if section:
                            result_sections.append(section)
                            
                elif section:
                    # This is a code section that we haven't processed yet - check if it's GraphQL
                    is_graphql = self._is_graphql_section(section)
                    
                    if is_graphql:
                        print("[DEBUG] Section " + str(i) + " is standalone GraphQL")
                        
                        # Clean up GraphQL section
                        graphql_section = self._clean_graphql_section(section)
                        
                        # Check if this GraphQL section contains multiple variants with comments
                        parsed_variants = self._parse_variants_from_graphql_block(graphql_section)
                        
                        if len(parsed_variants) > 1:
                            print("[DEBUG] Found " + str(len(parsed_variants)) + " variants within GraphQL block")
                            result_sections.extend(parsed_variants)
                        else:
                            # Single query - convert to single line format
                            single_line_query = self._convert_to_single_line(graphql_section.strip())
                            result_sections.append(single_line_query)
                        
                        try:
                            preview = str(len(parsed_variants)) + " variants" if len(parsed_variants) > 1 else graphql_section[:150]
                            print("[DEBUG] Added GraphQL content: " + preview.encode('utf-8', 'replace') + "...")
                        except:
                            print("[DEBUG] Added GraphQL content (encoding issue)")
                    else:
                        print("[DEBUG] Section " + str(i) + " is non-GraphQL content")
                        result_sections.append(section)
                
                i += 1
            
            # If no structured results found, try alternative extraction with context preservation
            if len(result_sections) == 0:
                print("[DEBUG] No structured results found, trying alternative extraction...")
                result_sections = self._alternative_extraction_with_context(content)
            
            print("[DEBUG] Final extraction result: " + str(len(result_sections)) + " sections")
            for i, section in enumerate(result_sections):
                try:
                    section_preview = section[:150].encode('utf-8', 'replace')
                    print("[DEBUG] Section " + str(i+1) + ": " + section_preview + "...")
                except:
                    print("[DEBUG] Section " + str(i+1) + " (encoding issue)")
            
            return result_sections
            
        except Exception as e:
            print("[DEBUG] Error in _extract_queries_from_response: " + str(e))
            print("[DEBUG] Falling back to alternative extraction")
            return self._alternative_extraction_with_context(content)

    def _is_graphql_section(self, section):
        """Check if a section contains GraphQL content"""
        if not section:
            return False
        
        section_lower = section.lower().strip()
        
        # Handle sections that start with "graphql" language identifier
        if section_lower.startswith('graphql'):
            # Look for GraphQL keywords after the "graphql" identifier
            remaining_content = section_lower[7:].strip()  # Remove "graphql" prefix
            return (remaining_content.startswith('query') or 
                   remaining_content.startswith('mutation') or 
                   remaining_content.startswith('{') or
                   ('query' in remaining_content and '{' in remaining_content) or
                   ('mutation' in remaining_content and '{' in remaining_content))
        
        # Direct GraphQL detection
        return (section.strip().startswith('query') or 
               section.strip().startswith('mutation') or 
               section.strip().startswith('{') or
               ('query' in section_lower and '{' in section) or
               ('mutation' in section_lower and '{' in section))

    def _clean_graphql_section(self, section):
        """Clean up GraphQL section by removing language identifiers"""
        if not section:
            return section
        
        lines = section.split('\n')
        cleaned_lines = []
        
        for line in lines:
            line_lower = line.lower().strip()
            # Skip lines that are just language identifiers
            if line_lower in ['graphql', 'gql']:
                continue
            cleaned_lines.append(line)
        
        return '\n'.join(cleaned_lines)

    def _parse_variants_from_graphql_block(self, graphql_block):
        """Parse individual variants from a GraphQL block that contains multiple queries with comments"""
        print("[DEBUG] _parse_variants_from_graphql_block called")
        
        variants = []
        lines = graphql_block.split('\n')
        current_variant_lines = []
        current_description = ""
        
        i = 0
        while i < len(lines):
            line = lines[i].strip()
            
            # Look for variant descriptions in comments
            if line.startswith('#') and ('variant' in line.lower() or 'attempt' in line.lower() or 'bypass' in line.lower() or 'injection' in line.lower() or 'exfiltration' in line.lower()):
                # This is likely a variant description
                if current_variant_lines:
                    # Process the previous variant
                    variant_query = '\n'.join(current_variant_lines).strip()
                    if variant_query:
                        single_line_query = self._convert_to_single_line(variant_query)
                        if current_description:
                            combined_variant = current_description + "\n" + single_line_query
                        else:
                            combined_variant = single_line_query
                        variants.append(combined_variant)
                        print("[DEBUG] Added variant: " + current_description[:50] + "..." if current_description else "No description")
                
                # Start new variant
                current_description = line
                current_variant_lines = []
                
                # Look ahead for additional description lines
                j = i + 1
                while j < len(lines) and lines[j].strip().startswith('#'):
                    current_description += "\n" + lines[j].strip()
                    j += 1
                i = j - 1  # Will be incremented at end of loop
                
            elif line.startswith('#'):
                # Regular comment line within a query
                if current_variant_lines:
                    current_variant_lines.append(lines[i])
                    
            elif line and (line.startswith('query') or line.startswith('mutation') or line.startswith('{')):
                # Start of a GraphQL query/mutation
                current_variant_lines = [lines[i]]
                
                # Collect the rest of the query until we find the closing brace
                brace_count = line.count('{') - line.count('}')
                j = i + 1
                
                while j < len(lines) and brace_count > 0:
                    query_line = lines[j]
                    current_variant_lines.append(query_line)
                    brace_count += query_line.count('{') - query_line.count('}')
                    j += 1
                
                i = j - 1  # Will be incremented at end of loop
                
            elif current_variant_lines and line:
                # Part of current query
                current_variant_lines.append(lines[i])
            
            i += 1
        
        # Process the last variant if any
        if current_variant_lines:
            variant_query = '\n'.join(current_variant_lines).strip()
            if variant_query:
                single_line_query = self._convert_to_single_line(variant_query)
                if current_description:
                    combined_variant = current_description + "\n" + single_line_query
                else:
                    combined_variant = single_line_query
                variants.append(combined_variant)
                print("[DEBUG] Added final variant: " + current_description[:50] + "..." if current_description else "No description")
        
        print("[DEBUG] Total variants parsed: " + str(len(variants)))
        return variants

    def _alternative_extraction_with_context(self, content):
        """Alternative extraction method that preserves context around GraphQL queries"""
        print("[DEBUG] _alternative_extraction_with_context called")
        
        result_sections = []
        lines = content.split('\n')
        current_context = []
        current_query = []
        in_query = False
        
        for i, line in enumerate(lines):
            line_stripped = line.strip()
            
            if not in_query:
                # Look for query/mutation start
                if ('query' in line.lower() or 'mutation' in line.lower()) and '{' in line:
                    print("[DEBUG] Alternative: Found query/mutation start: " + line)
                    in_query = True
                    current_query = [line]
                    
                    # Add accumulated context if any
                    if current_context:
                        context_text = '\n'.join(current_context).strip()
                        if context_text:
                            print("[DEBUG] Alternative: Adding context: " + context_text[:100] + "...")
                else:
                    # Accumulate potential context
                    if line_stripped:
                        current_context.append(line)
                        # Keep only recent context (last 5 lines)
                        if len(current_context) > 5:
                            current_context.pop(0)
            else:
                # We're inside a query
                current_query.append(line)
                if '}' in line and line.count('}') >= line.count('{'):
                    # Query ended
                    multi_line_query = '\n'.join(current_query)
                    print("[DEBUG] Alternative: Converting multi-line query to single line")
                    single_line_query = self._convert_to_single_line(multi_line_query)
                    
                    # Combine context with single-line query
                    if current_context:
                        context_text = '\n'.join(current_context).strip()
                        combined_result = context_text + "\n" + single_line_query
                    else:
                        combined_result = single_line_query
                    
                    result_sections.append(combined_result)
                    print("[DEBUG] Alternative: Added result: " + combined_result[:150] + "...")
                    
                    # Reset for next query
                    current_context = []
                    current_query = []
                    in_query = False
        
        print("[DEBUG] Alternative extraction found: " + str(len(result_sections)) + " results")
        return result_sections

    def _convert_to_single_line(self, graphql_query):
        """Convert multi-line GraphQL query to single-line format while preserving syntax"""
        print("[DEBUG] _convert_to_single_line called with query length: " + str(len(graphql_query) if graphql_query else 0))
        print("[DEBUG] Input query preview: " + str(graphql_query[:200] if graphql_query else "None") + "...")
        
        if not graphql_query:
            print("[DEBUG] Empty query, returning as-is")
            return graphql_query
        
        # Remove comments first
        lines = []
        for line in graphql_query.split('\n'):
            # Remove comments but preserve the rest of the line
            if '#' in line:
                comment_pos = line.find('#')
                line = line[:comment_pos]
            lines.append(line.strip())
        
        print("[DEBUG] After comment removal and strip, lines: " + str(lines))
        
        # Join lines and clean up whitespace
        single_line = ' '.join(lines)
        print("[DEBUG] After joining lines: " + single_line)
        
        # Clean up extra spaces around GraphQL syntax elements
        import re
        
        # Remove extra spaces around brackets and braces
        single_line = re.sub(r'\s*{\s*', ' { ', single_line)
        single_line = re.sub(r'\s*}\s*', ' } ', single_line)
        single_line = re.sub(r'\s*\(\s*', '(', single_line)
        single_line = re.sub(r'\s*\)\s*', ') ', single_line)
        
        # Clean up spaces around colons and commas
        single_line = re.sub(r'\s*:\s*', ': ', single_line)
        single_line = re.sub(r'\s*,\s*', ', ', single_line)
        
        # Remove extra spaces
        single_line = re.sub(r'\s+', ' ', single_line)
        
        # Clean up leading/trailing spaces
        single_line = single_line.strip()
        
        print("[DEBUG] Final single-line result: " + single_line)
        print("[DEBUG] Single-line conversion complete, length: " + str(len(single_line)))
        return single_line

    def _test_llm_connection(self, llm_endpoint, model_name, api_key):
        """Test LLM connection with minimal payload"""
        print("[DEBUG] Testing LLM connection with minimal payload...")
        test_payload = {
            "model": model_name,
            "messages": [{"role": "user", "content": "Hello, respond with just 'Hi'"}],
            "max_tokens": 10,
            "temperature": 0.1
        }
        
        try:
            result = self._execute_llm_request(llm_endpoint, model_name, api_key, test_payload)
            print("[DEBUG] LLM connection test successful!")
            return True
        except Exception as e:
            print("[DEBUG] LLM connection test failed: " + str(e))
            return False

    def _execute_llm_request(self, llm_endpoint, model_name, api_key, payload):
        """Execute LLM API request with retry logic - supports both local and cloud LLMs"""
        from java.net import URL
        
        # Determine if this is OpenAI or OpenAI-compatible format
        is_openai = "openai.com" in llm_endpoint
        is_openai_compatible = (
            "/v1/chat/completions" in llm_endpoint or
            ":1234" in llm_endpoint or  # LM Studio
            "localhost:1234" in llm_endpoint or
            "127.0.0.1:1234" in llm_endpoint or
            "vllm" in llm_endpoint.lower() or
            "lm-studio" in llm_endpoint.lower()
        )
        
        print("[DEBUG] LLM endpoint: " + llm_endpoint)
        print("[DEBUG] Is OpenAI: " + str(is_openai))
        print("[DEBUG] Is OpenAI compatible: " + str(is_openai_compatible))
        print("[DEBUG] Model name: " + model_name)
        
        if is_openai or is_openai_compatible:
            # OpenAI format - use provided payload as-is
            url = URL(llm_endpoint)
            data = json.dumps(payload)
            print("[DEBUG] Using OpenAI-compatible format")
            print("[DEBUG] Request payload keys: " + str(payload.keys()))
            print("[DEBUG] Request payload preview: " + json.dumps(payload)[:300] + "...")
        else:
            # Local LLM format (Ollama, etc.) - convert to local format
            url = URL(llm_endpoint)
            
            # Different local LLM formats based on endpoint
            if "ollama" in llm_endpoint.lower() or ":11434" in llm_endpoint or "/api/generate" in llm_endpoint:
                # Ollama format
                local_payload = {
                    "model": payload.get("model", model_name),
                    "prompt": self._convert_messages_to_prompt(payload.get("messages", [])),
                    "stream": False,
                    "options": {
                        "temperature": payload.get("temperature", 0.7),
                        "num_predict": payload.get("max_tokens", 1500)
                    }
                }
            elif "text-generation-webui" in llm_endpoint.lower() or ":5000" in llm_endpoint:
                # Text Generation WebUI format
                local_payload = {
                    "prompt": self._convert_messages_to_prompt(payload.get("messages", [])),
                    "max_new_tokens": payload.get("max_tokens", 1500),
                    "temperature": payload.get("temperature", 0.7),
                    "do_sample": True,
                    "stream": False
                }
            elif "/completions" in llm_endpoint or "/complete" in llm_endpoint:
                # Generic completion API
                local_payload = {
                    "prompt": self._convert_messages_to_prompt(payload.get("messages", [])),
                    "max_tokens": payload.get("max_tokens", 1500),
                    "temperature": payload.get("temperature", 0.7),
                    "stream": False
                }
            else:
                # Generic local LLM format - try Ollama-style first
                local_payload = {
                    "model": payload.get("model", model_name),
                    "prompt": self._convert_messages_to_prompt(payload.get("messages", [])),
                    "stream": False,
                    "options": {
                        "temperature": payload.get("temperature", 0.7),
                        "num_predict": payload.get("max_tokens", 1500)
                    }
                }
            
            data = json.dumps(local_payload)
            print("[DEBUG] Using local LLM format")
            print("[DEBUG] Local payload: " + data[:500] + "...")
        
        host = url.getHost()
        port = url.getPort() if url.getPort() != -1 else (443 if url.getProtocol() == "https" else 80)
        use_https = url.getProtocol() == "https"
        
        # Create HTTP service
        http_service = self.helpers.buildHttpService(host, port, use_https)
        
        # Extract path from URL for proper HTTP request
        path = url.getPath()
        if not path:
            path = "/"
        
        # Build complete HTTP request manually
        http_method = "POST"
        http_version = "HTTP/1.1"
        
        # Build headers
        headers = [
            http_method + " " + path + " " + http_version,
            "Host: " + host,
            "Content-Type: application/json",
            "User-Agent: GraphQL-Security-Tester/1.0",
            "Content-Length: " + str(len(data.encode('utf-8')))
        ]
        
        # Add authorization header if API key is provided
        if api_key and api_key.strip():
            if is_openai or is_openai_compatible:
                headers.append("Authorization: Bearer " + api_key)
            else:
                # Some local LLMs might use different auth formats
                headers.append("Authorization: Bearer " + api_key)
        
        # Add empty line and body
        headers.append("")
        headers.append(data)
        
        # Build complete request
        request_str = "\r\n".join(headers)
        request = self.helpers.stringToBytes(request_str)
        
        # Debug the complete HTTP request
        request_str = self.helpers.bytesToString(request)
        print("[DEBUG] Complete HTTP request:")
        print("[DEBUG] " + request_str.replace('\n', '\\n')[:500] + "...")
        
        # Retry logic
        max_retries = 3
        for attempt in range(max_retries):
            try:
                print("[DEBUG] Making LLM API request (attempt " + str(attempt + 1) + ")...")
                response = self.callbacks.makeHttpRequest(http_service, request)
                response_info = self.helpers.analyzeResponse(response.getResponse())
                status_code = response_info.getStatusCode()
                
                print("[DEBUG] Response status: " + str(status_code))
                
                # Always try to get the full response for debugging
                if status_code != 200:
                    try:
                        full_response = self.helpers.bytesToString(response.getResponse())
                        print("[DEBUG] Full error response: " + full_response[:1000])
                    except Exception as debug_e:
                        print("[DEBUG] Could not read full response: " + str(debug_e))
                
                if status_code == 200:
                    response_body = response.getResponse()[response_info.getBodyOffset():]
                    response_str = self.helpers.bytesToString(response_body)
                    result = json.loads(response_str)
                    
                    # Convert local LLM response to OpenAI format if needed
                    if not is_openai and not is_openai_compatible:
                        result = self._convert_local_response_to_openai_format(result)
                    
                    print("[DEBUG] LLM API request successful")
                    return result
                elif status_code == 429 and attempt < max_retries - 1:
                    wait_time = (2 ** attempt) * 5
                    print("[DEBUG] Rate limited, waiting " + str(wait_time) + " seconds...")
                    time.sleep(wait_time)
                    continue
                else:
                    # Get error response body for debugging
                    error_body = ""
                    try:
                        if response_info.getBodyOffset() < len(response.getResponse()):
                            error_response_body = response.getResponse()[response_info.getBodyOffset():]
                            error_body = self.helpers.bytesToString(error_response_body)
                            print("[DEBUG] Error response body: " + error_body[:500])
                        else:
                            print("[DEBUG] No response body available")
                    except Exception as e:
                        print("[DEBUG] Could not read error response: " + str(e))
                    
                    # Get response headers for more debugging info
                    try:
                        headers_section = response.getResponse()[:response_info.getBodyOffset()]
                        headers_str = self.helpers.bytesToString(headers_section)
                        print("[DEBUG] Response headers: " + headers_str[:300])
                    except Exception as e:
                        print("[DEBUG] Could not read headers: " + str(e))
                    
                    raise Exception("HTTP " + str(status_code) + " error from LLM API. Response: " + error_body[:200])
                    
            except Exception as e:
                if attempt == max_retries - 1:
                    print("[DEBUG] All attempts failed: " + str(e))
                    raise e
                else:
                    print("[DEBUG] Attempt failed, retrying: " + str(e))
                    time.sleep(2)
    
    def _convert_messages_to_prompt(self, messages):
        """Convert OpenAI messages format to single prompt for local LLMs"""
        prompt = ""
        for message in messages:
            role = message.get("role", "user")
            content = message.get("content", "")
            if role == "system":
                prompt += "System: " + content + "\n\n"
            elif role == "user":
                prompt += "Human: " + content + "\n\n"
            elif role == "assistant":
                prompt += "Assistant: " + content + "\n\n"
        prompt += "Assistant: "
        return prompt
    
    def _convert_local_response_to_openai_format(self, local_response):
        """Convert local LLM response to OpenAI-compatible format"""
        print("[DEBUG] Converting local response, keys: " + str(local_response.keys() if isinstance(local_response, dict) else "not dict"))
        
        # Already in OpenAI format
        if isinstance(local_response, dict) and "choices" in local_response:
            return local_response
        
        # Handle Ollama format
        if isinstance(local_response, dict) and "response" in local_response:
            return {
                "choices": [{
                    "message": {
                        "content": local_response["response"]
                    }
                }]
            }
        
        # Handle Text Generation WebUI format
        if isinstance(local_response, dict) and "results" in local_response:
            if local_response["results"] and len(local_response["results"]) > 0:
                text = local_response["results"][0].get("text", "")
                return {
                    "choices": [{
                        "message": {
                            "content": text
                        }
                    }]
                }
        
        # Handle other formats - try to find response text
        response_text = ""
        if isinstance(local_response, dict):
            if "text" in local_response:
                response_text = local_response["text"]
            elif "output" in local_response:
                response_text = local_response["output"]
            elif "content" in local_response:
                response_text = local_response["content"]
            elif "generated_text" in local_response:
                response_text = local_response["generated_text"]
            else:
                response_text = str(local_response)
        elif isinstance(local_response, str):
            response_text = local_response
        else:
            response_text = str(local_response)
        
        return {
            "choices": [{
                "message": {
                    "content": response_text
                }
            }]
        }

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

    def _get_offline_variants(self, target_query, schema, test_types):
        """Generate basic offline variants of the target query"""
        variants = []
        
        # Add the original query as reference (convert to single line)
        original_single_line = self._convert_to_single_line(target_query)
        variants.append("# Original query: " + original_single_line)
        
        # Try to create simple malicious variants
        import re
        
        # Look for string parameters and add injection payloads
        if 'id:' in target_query:
            # SQL injection variant
            injected = re.sub(r'id:\s*"[^"]*"', 'id: "1\' OR \'1\'=\'1"', target_query)
            injected_single_line = self._convert_to_single_line(injected)
            variants.append("# SQL Injection variant: " + injected_single_line)
            
            # XSS variant
            xss_injected = re.sub(r'id:\s*"[^"]*"', 'id: "<script>alert(1)</script>"', target_query)
            xss_single_line = self._convert_to_single_line(xss_injected)
            variants.append("# XSS variant: " + xss_single_line)
        
        # If it's a mutation, try to add malicious fields
        if target_query.strip().startswith('mutation'):
            # Try to add __typename for information disclosure
            if '{' in target_query and '__typename' not in target_query:
                lines = target_query.split('\n')
                for i, line in enumerate(lines):
                    if '{' in line and line.strip() != '{':
                        lines.insert(i+1, '    __typename')
                        break
                info_variant = '\n'.join(lines)
                info_single_line = self._convert_to_single_line(info_variant)
                variants.append("# Information disclosure variant: " + info_single_line)
        
        return variants[:5]  # Limit variants

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
            
            # This is a GraphQL query/mutation from proxy request
            if isinstance(schema.get('query'), (str, unicode)):
                print("[DEBUG] Found GraphQL query/mutation from proxy, analyzing...")
                query_text = schema.get('query', '')
                
                # Extract actual field names and types from the query/mutation
                extracted_fields = []
                extracted_types = []
                extracted_mutations = []
                
                # Look for mutation operations
                if query_text.strip().startswith('mutation'):
                    # Extract mutation name and fields
                    lines = query_text.split('\n')
                    for line in lines:
                        line = line.strip()
                        if line and not line.startswith('#'):
                            # Find mutation calls like "deriveCrossSells(input: $input)"
                            if '(' in line and '{' not in line and line != 'mutation' and not line.startswith('mutation '):
                                mutation_name = line.split('(')[0].strip()
                                if mutation_name and not mutation_name.startswith('...') and not mutation_name.startswith('__'):
                                    extracted_mutations.append(mutation_name)
                                    print("[DEBUG] Found mutation: " + mutation_name)
                
                # Extract field names from the query structure
                import re
                # Find all field references in the query
                field_pattern = r'\b([a-zA-Z][a-zA-Z0-9_]*)\s*{'
                matches = re.findall(field_pattern, query_text)
                for match in matches:
                    if match not in ['mutation', 'query', 'subscription'] and not match.startswith('__'):
                        extracted_fields.append(match)
                
                # Extract type names from fragments and field selections
                type_pattern = r'fragment\s+\w+\s+on\s+([A-Z][a-zA-Z0-9_]*)'
                type_matches = re.findall(type_pattern, query_text)
                extracted_types.extend(type_matches)
                
                # Extract variable types from the query definition
                var_pattern = r'\$\w+:\s*([A-Z][a-zA-Z0-9_]*!?)'
                var_matches = re.findall(var_pattern, query_text)
                extracted_types.extend([t.replace('!', '') for t in var_matches])
                
                # Also look at variables if present
                if 'variables' in schema and isinstance(schema['variables'], dict):
                    for var_name, var_value in schema['variables'].items():
                        if isinstance(var_value, dict):
                            for key in var_value.keys():
                                extracted_fields.append(key)
                
                # Remove duplicates and create summary
                unique_mutations = list(set(extracted_mutations))
                unique_fields = list(set(extracted_fields))
                unique_types = list(set(extracted_types))
                
                if unique_mutations:
                    summary.append("Mutation operations: " + ', '.join(unique_mutations))
                if unique_fields:
                    summary.append("Fields referenced: " + ', '.join(unique_fields[:10]))  # Limit to first 10
                if unique_types:
                    summary.append("Types used: " + ', '.join(unique_types[:8]))  # Limit to first 8
                
                # Add the actual query context for better understanding
                summary.append("Query context: This is a " + ("mutation" if query_text.strip().startswith('mutation') else "query") + " operation")
                
                print("[DEBUG] Extracted mutations: " + str(unique_mutations))
                print("[DEBUG] Extracted fields: " + str(unique_fields))
                print("[DEBUG] Extracted types: " + str(unique_types))
                
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