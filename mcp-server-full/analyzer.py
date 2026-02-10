import sys
import json
import re
import os

# Add the directory containing this script to the path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from rules import get_rules, get_rules_for_language, get_rule_stats

# File extension to language mapping
EXTENSION_MAP = {
    '.py': 'python',
    '.js': 'javascript',
    '.ts': 'typescript',
    '.tsx': 'typescript',
    '.jsx': 'javascript',
    '.java': 'java',
    '.go': 'go',
    '.rb': 'ruby',
    '.php': 'php',
    '.cs': 'csharp',
    '.rs': 'rust',
    '.c': 'c',
    '.cpp': 'cpp',
    '.h': 'c',
    '.hpp': 'cpp',
    '.sql': 'sql',
    '.dockerfile': 'dockerfile',
    '.yaml': 'yaml',
    '.yml': 'yaml',
    '.json': 'json',
    '.tf': 'terraform',
    '.hcl': 'terraform',
    # Prompt/text file extensions for prompt injection scanning
    '.txt': 'generic',
    '.md': 'generic',
    '.prompt': 'generic',
    '.jinja': 'generic',
    '.jinja2': 'generic',
    '.j2': 'generic',
}

def detect_language(file_path):
    """Detect the programming language from file extension or name"""
    basename = os.path.basename(file_path).lower()
    
    if basename == 'dockerfile' or basename.startswith('dockerfile.'):
        return 'dockerfile'
    
    _, ext = os.path.splitext(file_path.lower())
    return EXTENSION_MAP.get(ext, 'generic')

def analyze_file(file_path):
    """Analyze a single file for security vulnerabilities"""
    issues = []
    
    try:
        language = detect_language(file_path)
        rules = get_rules_for_language(language)
        
        with open(file_path, 'r', encoding='utf-8') as f:
            lines = f.readlines()
            content = ''.join(lines)
        
        for line_index, line in enumerate(lines):
            original_line = line
            line = line.strip()
            if not line:
                continue
            
            # Skip comment-only lines (basic detection)
            if line.startswith('#') or line.startswith('//') or line.startswith('*'):
                continue
                
            for rule_id, rule in rules.items():
                for pattern in rule['patterns']:
                    try:
                        # Use IGNORECASE for better detection (API_KEY vs api_key)
                        matches = re.finditer(pattern, line, re.IGNORECASE)
                        for match in matches:
                            # Calculate column based on original line (preserve indentation)
                            col_offset = len(original_line) - len(original_line.lstrip())
                            issues.append({
                                'ruleId': rule['id'],
                                'message': f"[{rule['name']}] {rule['message']}",
                                'line': line_index,
                                'column': match.start() + col_offset,
                                'length': match.end() - match.start(),
                                'severity': rule['severity'],
                                'metadata': rule.get('metadata', {})
                            })
                    except re.error:
                        # Skip invalid regex patterns
                        continue
                        
    except Exception as e:
        return {'error': str(e)}
    
    # Deduplicate issues (same rule, same line)
    seen = set()
    unique_issues = []
    for issue in issues:
        key = (issue['ruleId'], issue['line'], issue['column'])
        if key not in seen:
            seen.add(key)
            unique_issues.append(issue)
        
    return unique_issues

def main():
    if len(sys.argv) < 2:
        print(json.dumps({'error': 'No file path provided'}))
        sys.exit(1)
        
    file_path = sys.argv[1]
    
    if not os.path.exists(file_path):
        print(json.dumps({'error': f'File not found: {file_path}'}))
        sys.exit(1)
        
    results = analyze_file(file_path)
    print(json.dumps(results))

if __name__ == '__main__':
    main()
