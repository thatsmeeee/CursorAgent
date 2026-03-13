<?php
/**
 * Simple Web Interface for PHP Security Agent
 * Upload and scan PHP files through your browser
 */

?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>PHP Security Agent - Web Scanner</title>
    <style>
        body { font-family: Arial, sans-serif; max-width: 1200px; margin: 0 auto; padding: 20px; }
        .upload-area { border: 2px dashed #ccc; padding: 40px; text-align: center; margin: 20px 0; }
        .upload-area.dragover { border-color: #007cba; background: #f0f8ff; }
        .results { margin-top: 20px; }
        .vulnerability { padding: 10px; margin: 10px 0; border-left: 4px solid; }
        .critical { border-color: #dc3545; background: #f8d7da; }
        .high { border-color: #fd7e14; background: #fff3cd; }
        .medium { border-color: #ffc107; background: #fff3cd; }
        .low { border-color: #17a2b8; background: #d1ecf1; }
        .code { background: #f8f9fa; padding: 10px; font-family: monospace; overflow-x: auto; }
        .score { font-size: 24px; font-weight: bold; text-align: center; margin: 20px 0; }
        button { background: #007cba; color: white; padding: 10px 20px; border: none; cursor: pointer; }
        button:hover { background: #005a87; }
        .file-list { max-height: 200px; overflow-y: auto; border: 1px solid #ddd; padding: 10px; }
    </style>
</head>
<body>
    <h1>🛡️ PHP Security Agent - Web Scanner</h1>
    
    <div class="upload-area" id="uploadArea">
        <h3>📁 Upload PHP Files or Drop Them Here</h3>
        <input type="file" id="fileInput" multiple accept=".php" style="display: none;">
        <button onclick="document.getElementById('fileInput').click()">Choose Files</button>
        <p>or drag and drop PHP files here</p>
    </div>

    <div class="file-list" id="fileList" style="display: none;">
        <h4>Selected Files:</h4>
        <div id="fileListContent"></div>
    </div>

    <button onclick="scanFiles()" id="scanBtn" style="display: none;">🔍 Scan Files</button>
    
    <div class="results" id="results"></div>

    <script>
        let uploadedFiles = [];

        // Drag and drop functionality
        const uploadArea = document.getElementById('uploadArea');
        const fileInput = document.getElementById('fileInput');

        uploadArea.addEventListener('dragover', (e) => {
            e.preventDefault();
            uploadArea.classList.add('dragover');
        });

        uploadArea.addEventListener('dragleave', () => {
            uploadArea.classList.remove('dragover');
        });

        uploadArea.addEventListener('drop', (e) => {
            e.preventDefault();
            uploadArea.classList.remove('dragover');
            handleFiles(e.dataTransfer.files);
        });

        fileInput.addEventListener('change', (e) => {
            handleFiles(e.target.files);
        });

        function handleFiles(files) {
            uploadedFiles = Array.from(files).filter(file => file.name.endsWith('.php'));
            displayFileList();
            document.getElementById('scanBtn').style.display = 'block';
        }

        function displayFileList() {
            const fileList = document.getElementById('fileList');
            const fileListContent = document.getElementById('fileListContent');
            
            if (uploadedFiles.length > 0) {
                fileList.style.display = 'block';
                fileListContent.innerHTML = uploadedFiles.map((file, index) => 
                    `<div>${index + 1}. ${file.name} (${formatFileSize(file.size)})</div>`
                ).join('');
            } else {
                fileList.style.display = 'none';
            }
        }

        function formatFileSize(bytes) {
            if (bytes === 0) return '0 Bytes';
            const k = 1024;
            const sizes = ['Bytes', 'KB', 'MB', 'GB'];
            const i = Math.floor(Math.log(bytes) / Math.log(k));
            return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
        }

        async function scanFiles() {
            if (uploadedFiles.length === 0) {
                alert('Please upload PHP files first');
                return;
            }

            const resultsDiv = document.getElementById('results');
            resultsDiv.innerHTML = '<h2>🔍 Scanning Files...</h2><p>This may take a few moments...</p>';

            const formData = new FormData();
            uploadedFiles.forEach((file, index) => {
                formData.append(`files[${index}]`, file);
            });

            try {
                const response = await fetch('scan_handler.php', {
                    method: 'POST',
                    body: formData
                });

                const result = await response.json();
                displayResults(result);
            } catch (error) {
                resultsDiv.innerHTML = `<h2>❌ Error</h2><p>${error.message}</p>`;
            }
        }

        function displayResults(result) {
            const resultsDiv = document.getElementById('results');
            
            if (result.error) {
                resultsDiv.innerHTML = `<h2>❌ Error</h2><p>${result.error}</p>`;
                return;
            }

            let html = `
                <h2>📊 Scan Results</h2>
                <div class="score">Performance Score: ${result.score}/10,000</div>
                <p><strong>Files scanned:</strong> ${result.files_scanned}</p>
                <p><strong>Vulnerabilities found:</strong> ${result.vulnerabilities.length}</p>
            `;

            if (result.vulnerabilities.length > 0) {
                // Group by severity
                const grouped = {};
                result.vulnerabilities.forEach(vuln => {
                    if (!grouped[vuln.severity]) {
                        grouped[vuln.severity] = [];
                    }
                    grouped[vuln.severity].push(vuln);
                });

                Object.keys(grouped).forEach(severity => {
                    html += `<h3>${severity.toUpperCase()} (${grouped[severity].length})</h3>`;
                    grouped[severity].forEach(vuln => {
                        html += `
                            <div class="vulnerability ${severity.toLowerCase()}">
                                <h4>${vuln.type}</h4>
                                <p><strong>File:</strong> ${vuln.file}</p>
                                <p><strong>Line:</strong> ${vuln.line}</p>
                                <p><strong>Description:</strong> ${vuln.description}</p>
                                <p><strong>Fix:</strong> ${vuln.fix_suggestion}</p>
                                <p><strong>Confidence:</strong> ${Math.round(vuln.confidence * 100)}%</p>
                                <div class="code">${vuln.code_snippet}</div>
                            </div>
                        `;
                    });
                });
            } else {
                html += '<div class="vulnerability low"><h3>✅ No vulnerabilities found!</h3></div>';
            }

            resultsDiv.innerHTML = html;
        }
    </script>
</body>
</html>
