<?php
require_once __DIR__ . '/../src/helpers.php';

$pageTitle = "About Our Application";
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title><?= htmlspecialchars($pageTitle) ?></title>
    <link rel="stylesheet" href="/css/style.css">
</head>
<body>
    <header>
        <h1><?= htmlspecialchars($pageTitle) ?></h1>
        <nav>
            <ul>
                <li><a href="/index.php">Home</a></li>
                <li><a href="/about.php">About</a></li>
            </ul>
        </nav>
    </header>
    
    <main>
        <section>
            <h2>About This Application</h2>
            <p>This is a modern PHP 8 frontend application running with Nginx and FastCGI.</p>
            <p>Key features:</p>
            <ul>
                <li>PHP 8.2 for optimal performance</li>
                <li>Nginx as the web server</li>
                <li>FastCGI for efficient PHP processing</li>
                <li>Docker containerization</li>
                <li>Kubernetes deployment with Helm</li>
                <li>CI/CD pipeline with Jenkins</li>
            </ul>
        </section>
    </main>
    
    <footer>
        <p>&copy; <?= date('Y') ?> PHP Frontend App. All rights reserved.</p>
    </footer>
</body>
</html>