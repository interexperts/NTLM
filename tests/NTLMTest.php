<?php

class NTLMTest extends \PHPUnit_Framework_TestCase {
    public function testStringToMD4(){	
        $this->assertEquals(pack("H*", "ef9283d532ca7d2bcb0ea119cef0ec15"), \InterExperts\NTLM\NTLM::toMD4('knownString'));
    }
}