<?php
use PHPUnit\Framework\TestCase;

class SampleTest extends TestCase
{
    public function testPageTitleFormatting()
    {
        $pageTitle = "About Us";
        $expected = "About Us";
        $this->assertEquals($expected, $pageTitle);
    }
    
    public function testImageArrayStructure()
    {
        $featuredImages = [
            'mountain-view.jpg' => 'Beautiful Mountain Landscape',
            'city-skyline.jpg' => 'Modern City Skyline'
        ];
        
        $this->assertIsArray($featuredImages);
        $this->assertArrayHasKey('mountain-view.jpg', $featuredImages);
        $this->assertEquals('Modern City Skyline', $featuredImages['city-skyline.jpg']);
    }
    
    public function testCurrentYearDisplay()
    {
        $year = date('Y');
        $this->assertEquals(4, strlen($year));
        $this->assertGreaterThanOrEqual(2023, (int)$year);
    }
}