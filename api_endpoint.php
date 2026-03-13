<?php
/**
 * REST API endpoint for PHP Security Agent
 * Usage: POST /api/scan with file content or directory path
 */

header('Content-Type: application/json');
header('Access-Control-Allow-Origin: *');
header('Access-Control-Allow-Methods: POST, OPTIONS');
header('Access-Control-Allow-Headers: Content-Type');

if ($_SERVER['REQUEST_METHOD'] === 'OPTIONS') {
    exit(0);
}

if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    http_response_code(405);
    echo json_encode(['error' => 'Method not allowed']);
    exit;
}

try {
    $input = json_decode(file_get_contents('php://input'), true);
    
    if (!$input) {
        throw new Exception('Invalid JSON input');
    }

    // Handle different scan types
    if (isset($input['file_content'])) {
        // Scan single file content
        $result = scanContent($input['file_content'], $input['filename'] ?? 'unknown.php');
    } elseif (isset($input['directory'])) {
        // Scan directory
        $result = scanDirectory($input['directory']);
    } else {
        throw new Exception('Must provide file_content or directory');
    }

    echo json_encode($result);

} catch (Exception $e) {
    http_response_code(400);
    echo json_encode(['error' => $e->getMessage()]);
}

function scanContent($content, $filename) {
    // Save content to temporary file
    $tempFile = tempnam(sys_get_temp_dir(), 'php_scan_');
    file_put_contents($tempFile, $content);
    
    // Run scanner
    $output = shell_exec("python3 agent.py scan $tempFile --output - 2>/dev/null");
    
    // Clean up
    unlink($tempFile);
    
    // Parse results (simplified)
    $vulnerabilities = parseVulnerabilities($output);
    
    return [
        'filename' => $filename,
        'vulnerabilities' => $vulnerabilities,
        'score' => calculateScore($vulnerabilities, 1),
        'scan_time' => date('Y-m-d H:i:s')
    ];
}

function scanDirectory($directory) {
    if (!is_dir($directory)) {
        throw new Exception('Directory not found: ' . $directory);
    }
    
    // Run scanner on directory
    $output = shell_exec("python3 agent.py scan $directory --output - 2>/dev/null");
    
    // Parse results
    $vulnerabilities = parseVulnerabilities($output);
    $filesScanned = countFiles($directory, 'php');
    
    return [
        'directory' => $directory,
        'vulnerabilities' => $vulnerabilities,
        'files_scanned' => $filesScanned,
        'score' => calculateScore($vulnerabilities, $filesScanned),
        'scan_time' => date('Y-m-d H:i:s')
    ];
}

function parseVulnerabilities($output) {
    // Simplified parsing - in real implementation, parse JSON output
    $vulnerabilities = [];
    $lines = explode("\n", $output);
    
    foreach ($lines as $line) {
        if (strpos($line, 'SQL Injection') !== false) {
            $vulnerabilities[] = [
                'type' => 'SQL Injection',
                'severity' => 'HIGH',
                'description' => 'Potential SQL injection detected',
                'fix_suggestion' => 'Use prepared statements'
            ];
        }
        // Add more parsing logic for other vulnerability types
    }
    
    return $vulnerabilities;
}

function calculateScore($vulnerabilities, $filesScanned) {
    // Simplified score calculation
    $baseScore = 10000;
    $deduction = count($vulnerabilities) * 100;
    return max(0, $baseScore - $deduction);
}

function countFiles($dir, $extension) {
    $count = 0;
    $iterator = new RecursiveIteratorIterator(new RecursiveDirectoryIterator($dir));
    
    foreach ($iterator as $file) {
        if ($file->isFile() && $file->getExtension() === $extension) {
            $count++;
        }
    }
    
    return $count;
}
?>
