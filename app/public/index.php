<?php
require_once __DIR__ . '/../src/helpers.php';

$pageTitle = "Welcome to Our PHP Frontend";
$featuredImages = [
    'mountain-view.jpg' => 'Beautiful Mountain Landscape',
    'city-skyline.jpg' => 'Modern City Skyline',
    'beach-sunset.jpg' => 'Tropical Beach Sunset'
];
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
        <section class="hero">
            <h2>Discover Our Amazing Content</h2>
            <p>Welcome to our PHP-powered frontend running on PHP 8 with Nginx and FastCGI.</p>
        </section>
        
        <section class="gallery">
            <h3>Featured Images</h3>
            <div class="image-grid">
                <?php foreach ($featuredImages as $image => $alt) : ?>
                    <div class="image-item">
                        <img src="/images/<?= htmlspecialchars($image) ?>" alt="<?= htmlspecialchars($alt) ?>">
                        <p><?= htmlspecialchars($alt) ?></p>
                    </div>
                <?php endforeach; ?>
            </div>
        </section>
    </main>
    
    <footer>
        <p>&copy; <?= date('Y') ?> PHP Frontend App. All rights reserved.</p>
    </footer>
</body>
</html>