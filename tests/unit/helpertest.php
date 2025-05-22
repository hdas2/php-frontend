<?php
use PHPUnit\Framework\TestCase;

class HelperTest extends TestCase
{
    public function testSanitizeOutput()
    {
        $input = '<script>alert("xss")</script>';
        $expected = '&lt;script&gt;alert(&quot;xss&quot;)&lt;/script&gt;';
        $this->assertEquals($expected, sanitize_output($input));
        
        $input = "O'Reilly";
        $expected = "O&#039;Reilly";
        $this->assertEquals($expected, sanitize_output($input));
    }
    
    public function testSanitizeOutputWithNull()
    {
        $this->assertEquals('', sanitize_output(null));
    }
}