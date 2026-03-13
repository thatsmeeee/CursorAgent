"""
PHP Vulnerability Scanner - Core scanning logic
Detects security vulnerabilities in PHP code using pattern matching and AI analysis
"""

import re
import ast
import json
from pathlib import Path
from typing import List, Dict, Any, Optional
import requests
from dataclasses import dataclass

@dataclass
class Vulnerability:
    """Represents a detected vulnerability"""
    type: str
    severity: str
    file: str
    line: int
    code_snippet: str
    description: str
    fix_suggestion: str
    confidence: float

class PHPVulnerabilityScanner:
    """Main scanner class for PHP security vulnerabilities"""
    
    def __init__(self, api_provider: str = 'openai', api_key: str = None, verbose: bool = False):
        self.api_provider = api_provider
        self.api_key = api_key
        self.verbose = verbose
        
        # Vulnerability patterns
        self.sql_injection_patterns = [
            r'mysql_query\s*\(\s*\$.*\+.*\)',
            r'mysql_query\s*\(\s*["\'].*\$\w+.*["\']',
            r'query\s*\(\s*["\'].*\$\w+.*["\']',
            r'execute\s*\(\s*["\'].*\$\w+.*["\']',
            r'->query\s*\(\s*["\'].*\$\w+.*["\']',
            r'->execute\s*\(\s*.*\$.*\)',
        ]
        
        self.xss_patterns = [
            r'echo\s+.*\$.*;',
            r'print\s+.*\$.*;',
            r'<?=.*\$.*',
            r'htmlspecialchars\s*\(\s*\$.*,\s*ENT_QUOTES\s*\)',
            r'htmlentities\s*\(\s*\$.*,\s*ENT_QUOTES\s*\)',
        ]
        
        self.unsafe_function_patterns = [
            r'eval\s*\(',
            r'exec\s*\(',
            r'shell_exec\s*\(',
            r'system\s*\(',
            r'passthru\s*\(',
            r'file_get_contents\s*\(\s*["\'].*http.*["\']',
            r'unserialize\s*\(',
        ]
        
        self.input_validation_patterns = [
            r'\$_GET\[',
            r'\$_POST\[', 
            r'\$_REQUEST\[',
            r'\$_COOKIE\[',
            r'\$_FILES\[',
        ]
    
    def scan_target(self, target_path: Path) -> Dict[str, Any]:
        """Scan a file or directory for vulnerabilities"""
        results = {
            'scan_target': str(target_path),
            'vulnerabilities': [],
            'files_scanned': 0,
            'scan_time': None
        }
        
        if target_path.is_file() and target_path.suffix == '.php':
            php_files = [target_path]
        else:
            php_files = list(target_path.rglob('*.php'))
        
        for php_file in php_files:
            try:
                file_vulnerabilities = self.scan_file(php_file)
                results['vulnerabilities'].extend(file_vulnerabilities)
                results['files_scanned'] += 1
                
                if self.verbose:
                    print(f"Scanned: {php_file} - Found {len(file_vulnerabilities)} vulnerabilities")
                    
            except Exception as e:
                if self.verbose:
                    print(f"Error scanning {php_file}: {e}")
        
        # Sort vulnerabilities by severity
        severity_order = {'CRITICAL': 0, 'HIGH': 1, 'MEDIUM': 2, 'LOW': 3}
        results['vulnerabilities'].sort(
            key=lambda v: severity_order.get(v.severity, 4)
        )
        
        return results
    
    def scan_file(self, file_path: Path) -> List[Vulnerability]:
        """Scan a single PHP file for vulnerabilities"""
        vulnerabilities = []
        
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read()
                lines = content.split('\n')
        except Exception as e:
            if self.verbose:
                print(f"Could not read file {file_path}: {e}")
            return vulnerabilities
        
        # Check for SQL injection
        vulnerabilities.extend(self._check_sql_injection(file_path, lines))
        
        # Check for XSS
        vulnerabilities.extend(self._check_xss(file_path, lines))
        
        # Check for unsafe functions
        vulnerabilities.extend(self._check_unsafe_functions(file_path, lines))
        
        # Check for missing input validation
        vulnerabilities.extend(self._check_input_validation(file_path, lines))
        
        # Use AI for advanced analysis if API key is available
        if self.api_key:
            ai_vulnerabilities = self._ai_analysis(file_path, content)
            vulnerabilities.extend(ai_vulnerabilities)
        
        return vulnerabilities
    
    def _check_sql_injection(self, file_path: Path, lines: List[str]) -> List[Vulnerability]:
        """Check for SQL injection vulnerabilities"""
        vulnerabilities = []
        
        for line_num, line in enumerate(lines, 1):
            for pattern in self.sql_injection_patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    # Check if prepared statements are used
                    if not re.search(r'prepare\s*\(|execute\s*\(\s*:', line, re.IGNORECASE):
                        vulnerability = Vulnerability(
                            type="SQL Injection",
                            severity="HIGH",
                            file=str(file_path),
                            line=line_num,
                            code_snippet=line.strip(),
                            description="User input directly used in SQL query without proper escaping",
                            fix_suggestion="Use PDO prepared statements: $stmt = $pdo->prepare('SELECT * FROM users WHERE id = :id'); $stmt->execute(['id' => $user_id]);",
                            confidence=0.85
                        )
                        vulnerabilities.append(vulnerability)
        
        return vulnerabilities
    
    def _check_xss(self, file_path: Path, lines: List[str]) -> List[Vulnerability]:
        """Check for XSS vulnerabilities"""
        vulnerabilities = []
        
        for line_num, line in enumerate(lines, 1):
            # Look for direct output of user input
            if re.search(r'echo|print|<?=', line, re.IGNORECASE):
                if re.search(r'\$_GET|\$_POST|\$_REQUEST|\$_COOKIE', line, re.IGNORECASE):
                    # Check if output is properly escaped
                    if not re.search(r'htmlspecialchars|htmlentities|strip_tags', line, re.IGNORECASE):
                        vulnerability = Vulnerability(
                            type="Cross-Site Scripting (XSS)",
                            severity="HIGH",
                            file=str(file_path),
                            line=line_num,
                            code_snippet=line.strip(),
                            description="User input directly output without proper escaping",
                            fix_suggestion="Use htmlspecialchars(): echo htmlspecialchars($_GET['input'], ENT_QUOTES, 'UTF-8');",
                            confidence=0.90
                        )
                        vulnerabilities.append(vulnerability)
        
        return vulnerabilities
    
    def _check_unsafe_functions(self, file_path: Path, lines: List[str]) -> List[Vulnerability]:
        """Check for unsafe function usage"""
        vulnerabilities = []
        
        for line_num, line in enumerate(lines, 1):
            for pattern in self.unsafe_function_patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    vulnerability = Vulnerability(
                        type="Unsafe Function Usage",
                        severity="CRITICAL",
                        file=str(file_path),
                        line=line_num,
                        code_snippet=line.strip(),
                        description=f"Usage of potentially dangerous function: {pattern}",
                        fix_suggestion="Avoid using eval(), exec(), shell_exec(), system(), passthru(). Use safer alternatives or validate input strictly.",
                        confidence=0.95
                    )
                    vulnerabilities.append(vulnerability)
        
        return vulnerabilities
    
    def _check_input_validation(self, file_path: Path, lines: List[str]) -> List[Vulnerability]:
        """Check for missing input validation"""
        vulnerabilities = []
        
        input_usage_lines = []
        for line_num, line in enumerate(lines, 1):
            if re.search(r'\$_GET|\$_POST|\$_REQUEST|\$_COOKIE', line, re.IGNORECASE):
                input_usage_lines.append((line_num, line.strip()))
        
        # Check if input is used without validation
        for line_num, line in input_usage_lines:
            # Look for validation functions in the surrounding context
            validation_found = False
            context_start = max(0, line_num - 5)
            context_end = min(len(lines), line_num + 5)
            
            for i in range(context_start, context_end):
                if re.search(r'filter_var|ctype_|is_numeric|preg_match|htmlspecialchars|strip_tags', lines[i], re.IGNORECASE):
                    validation_found = True
                    break
            
            if not validation_found and not re.search(r'isset|empty', line):
                vulnerability = Vulnerability(
                    type="Missing Input Validation",
                    severity="MEDIUM",
                    file=str(file_path),
                    line=line_num,
                    code_snippet=line,
                    description="User input used without proper validation",
                    fix_suggestion="Validate input using filter_var() or custom validation: $email = filter_var($_POST['email'], FILTER_VALIDATE_EMAIL);",
                    confidence=0.70
                )
                vulnerabilities.append(vulnerability)
        
        return vulnerabilities
    
    def _ai_analysis(self, file_path: Path, content: str) -> List[Vulnerability]:
        """Use AI API for advanced vulnerability analysis"""
        vulnerabilities = []
        
        try:
            if self.api_provider == 'openai':
                vulnerabilities = self._openai_analysis(file_path, content)
            else:
                vulnerabilities = self._claude_analysis(file_path, content)
        except Exception as e:
            if self.verbose:
                print(f"AI analysis failed for {file_path}: {e}")
        
        return vulnerabilities
    
    def _openai_analysis(self, file_path: Path, content: str) -> List[Vulnerability]:
        """Analyze code using OpenAI API"""
        vulnerabilities = []
        
        prompt = f"""
        Analyze this PHP code for security vulnerabilities. Focus on:
        1. SQL injection risks
        2. XSS vulnerabilities  
        3. Unsafe database queries
        4. Missing input validation
        5. Authentication bypasses
        6. File inclusion vulnerabilities
        
        PHP code:
        {content[:2000]}  # Limit content to avoid token limits
        
        Return JSON response with vulnerabilities found, each containing:
        - type: vulnerability type
        - severity: CRITICAL/HIGH/MEDIUM/LOW
        - line: line number (approximate)
        - description: detailed description
        - fix_suggestion: specific fix recommendation
        - confidence: confidence score 0-1
        
        Only return actual vulnerabilities, no false positives.
        """
        
        headers = {
            'Authorization': f'Bearer {self.api_key}',
            'Content-Type': 'application/json'
        }
        
        data = {
            'model': 'gpt-3.5-turbo',
            'messages': [{'role': 'user', 'content': prompt}],
            'temperature': 0.1
        }
        
        response = requests.post(
            'https://api.openai.com/v1/chat/completions',
            headers=headers,
            json=data,
            timeout=30
        )
        
        if response.status_code == 200:
            result = response.json()
            ai_response = result['choices'][0]['message']['content']
            
            try:
                ai_vulns = json.loads(ai_response)
                for vuln in ai_vulns:
                    vulnerability = Vulnerability(
                        type=vuln.get('type', 'Unknown'),
                        severity=vuln.get('severity', 'MEDIUM'),
                        file=str(file_path),
                        line=vuln.get('line', 1),
                        code_snippet="AI-detected vulnerability",
                        description=vuln.get('description', ''),
                        fix_suggestion=vuln.get('fix_suggestion', ''),
                        confidence=vuln.get('confidence', 0.5)
                    )
                    vulnerabilities.append(vulnerability)
            except json.JSONDecodeError:
                if self.verbose:
                    print("Failed to parse AI response")
        
        return vulnerabilities
    
    def _claude_analysis(self, file_path: Path, content: str) -> List[Vulnerability]:
        """Analyze code using Claude API"""
        vulnerabilities = []
        
        prompt = f"""
        Analyze this PHP code for security vulnerabilities. Focus on SQL injection, XSS, unsafe queries, and input validation.
        
        Code: {content[:2000]}
        
        Return JSON array of vulnerabilities with type, severity, line, description, fix_suggestion, and confidence.
        """
        
        headers = {
            'x-api-key': self.api_key,
            'Content-Type': 'application/json',
            'anthropic-version': '2023-06-01'
        }
        
        data = {
            'model': 'claude-3-sonnet-20240229',
            'max_tokens': 1000,
            'messages': [{'role': 'user', 'content': prompt}]
        }
        
        response = requests.post(
            'https://api.anthropic.com/v1/messages',
            headers=headers,
            json=data,
            timeout=30
        )
        
        if response.status_code == 200:
            result = response.json()
            ai_response = result['content'][0]['text']
            
            try:
                ai_vulns = json.loads(ai_response)
                for vuln in ai_vulns:
                    vulnerability = Vulnerability(
                        type=vuln.get('type', 'Unknown'),
                        severity=vuln.get('severity', 'MEDIUM'),
                        file=str(file_path),
                        line=vuln.get('line', 1),
                        code_snippet="AI-detected vulnerability",
                        description=vuln.get('description', ''),
                        fix_suggestion=vuln.get('fix_suggestion', ''),
                        confidence=vuln.get('confidence', 0.5)
                    )
                    vulnerabilities.append(vulnerability)
            except json.JSONDecodeError:
                if self.verbose:
                    print("Failed to parse Claude response")
        
        return vulnerabilities
