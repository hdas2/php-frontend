<?php

/**
 * Application Helper Functions
 *
 * Contains utility functions used throughout the application
 */

if (!function_exists('sanitize_output')) {
    /**
     * Sanitizes output to prevent XSS attacks
     *
     * @param mixed $value The value to sanitize
     * @return string Sanitized string
     */
    function sanitize_output($value): string
    {
        if (is_null($value)) {
            return '';
        }

        return htmlspecialchars($value, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8', false);
    }
}

if (!function_exists('generate_csrf_token')) {
    /**
     * Generates a CSRF token and stores it in session
     *
     * @return string The generated token
     */
    function generate_csrf_token(): string
    {
        if (session_status() === PHP_SESSION_NONE) {
            session_start();
        }

        $token = bin2hex(random_bytes(32));
        $_SESSION['csrf_token'] = $token;
        return $token;
    }
}

if (!function_exists('validate_csrf_token')) {
    /**
     * Validates a submitted CSRF token
     *
     * @param string $token The token to validate
     * @return boolean True if valid, false otherwise
     */
    function validate_csrf_token(string $token): bool
    {
        if (session_status() === PHP_SESSION_NONE) {
            session_start();
        }

        return isset($_SESSION['csrf_token']) &&
               hash_equals($_SESSION['csrf_token'], $token);
    }
}

if (!function_exists('asset_path')) {
    /**
     * Generates a versioned asset path to prevent caching issues
     *
     * @param string $path The asset path
     * @return string Versioned asset path
     */
    function asset_path(string $path): string
    {
        static $manifest = null;
        $publicPath = __DIR__ . '/../public';

        if ($manifest === null && file_exists($publicPath . '/mix-manifest.json')) {
            $manifest = json_decode(file_get_contents($publicPath . '/mix-manifest.json'), true);
        }

        if ($manifest && isset($manifest[$path])) {
            return $manifest[$path];
        }

        return $path;
    }
}

if (!function_exists('redirect')) {
    /**
     * Redirects to a specified URL
     *
     * @param string  $url        URL to redirect to
     * @param integer $statusCode HTTP status code (default: 302)
     */
    function redirect(string $url, int $statusCode = 302): void
    {
        header("Location: $url", true, $statusCode);
        exit();
    }
}

if (!function_exists('json_response')) {
    /**
     * Sends a JSON response
     *
     * @param mixed   $data   Data to encode as JSON
     * @param integer $status HTTP status code
     */
    function json_response($data, int $status = 200): void
    {
        header('Content-Type: application/json');
        http_response_code($status);
        echo json_encode($data, JSON_HEX_TAG | JSON_HEX_APOS | JSON_HEX_QUOT | JSON_HEX_AMP);
        exit();
    }
}

if (!function_exists('is_ajax_request')) {
    /**
     * Checks if the request is an AJAX request
     *
     * @return boolean True if AJAX request, false otherwise
     */
    function is_ajax_request(): bool
    {
        return !empty($_SERVER['HTTP_X_REQUESTED_WITH']) &&
               strtolower($_SERVER['HTTP_X_REQUESTED_WITH']) === 'xmlhttprequest';
    }
}

if (!function_exists('get_current_url')) {
    /**
     * Gets the current URL
     *
     * @return string Current URL
     */
    function get_current_url(): string
    {
        $protocol = isset($_SERVER['HTTPS']) && $_SERVER['HTTPS'] === 'on' ? 'https' : 'http';
        return $protocol . '://' . $_SERVER['HTTP_HOST'] . $_SERVER['REQUEST_URI'];
    }
}

if (!function_exists('slugify')) {
    /**
     * Converts a string to a URL-friendly slug
     *
     * @param string $text Text to convert
     * @return string Generated slug
     */
    function slugify(string $text): string
    {
        $text = preg_replace('~[^\pL\d]+~u', '-', $text);
        $text = iconv('utf-8', 'us-ascii//TRANSLIT', $text);
        $text = preg_replace('~[^-\w]+~', '', $text);
        $text = trim($text, '-');
        $text = preg_replace('~-+~', '-', $text);
        $text = strtolower($text);

        return $text ?: 'n-a';
    }
}

if (!function_exists('format_date')) {
    /**
     * Formats a date string
     *
     * @param string $date   Date string
     * @param string $format Output format (default: 'F j, Y')
     * @return string Formatted date
     */
    function format_date(string $date, string $format = 'F j, Y'): string
    {
        $timestamp = strtotime($date);
        return $timestamp ? date($format, $timestamp) : '';
    }
}

if (!function_exists('get_file_extension')) {
    /**
     * Gets the file extension from a filename
     *
     * @param string $filename The filename
     * @return string File extension in lowercase
     */
    function get_file_extension(string $filename): string
    {
        return strtolower(pathinfo($filename, PATHINFO_EXTENSION));
    }
}

if (!function_exists('is_image_file')) {
    /**
     * Checks if a file is an image based on its extension
     *
     * @param string $filename The filename to check
     * @return boolean True if image, false otherwise
     */
    function is_image_file(string $filename): bool
    {
        $allowed = ['jpg', 'jpeg', 'png', 'gif', 'webp'];
        return in_array(get_file_extension($filename), $allowed);
    }
}
