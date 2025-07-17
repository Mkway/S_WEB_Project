<?php

use PHPUnit\Framework\TestCase;

class ExampleTest extends TestCase
{
    public function testAddition()
    {
        $this->assertEquals(2, 1 + 1);
    }

    public function testStringConcatenation()
    {
        $this->assertEquals("HelloWorld", "Hello" . "World");
    }
}