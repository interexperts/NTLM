<?php

class IPWhitelistTest extends \PHPUnit_Framework_TestCase {
    public $ntlmObject = null;

    public function setUp(){
    	$_SERVER['HTTP_AUTHORIZATION'] = 'NTLM TlRMTVNTUAADAAAAGAAYAG4AAAASARIBhgAAAAYABgBYAAAACgAKAF4AAAAGAAYAaAAAAAAAAACYAQAABQKAAgYDgCUAAAAP5VQScilF+FdimsHOnQS7fk4AQgBMAGEAZABtAGkAbgBOAEIATAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABPXUvNaz0xMZF9AAySpcl2AQEAAAAAAAB1+1LJ507QAeCrR1SzQl4pAAAAAAIAAAABABQAbQB5AGMAbwBtAHAAdQB0AGUAcgAEACAAdABlAHMAdABkAG8AbQBhAGkAbgAuAGwAbwBjAGEAbAADACAAbQB5AGMAbwBtAHAAdQB0AGUAcgAuAGwAbwBjAGEAbAAIADAAMAAAAAAAAAABAAAAACAAAKZQUgL77gVAvoZTBPma52m1ag8i/CLRhvKkIk0MQSZBCgAQAAAAAAAAAAAAAAAAAAAAAAAJACoASABUAFQAUAAvAG4AdABsAG0ALgBsAGkAYgByAGEAcgB5AC4AZABlAHYAAAAAAAAAAAAAAAAA';
    	$_SESSION['_ntlm_server_challenge'] = 'test';
    	$ntlm = new \InterExperts\NTLM\NTLM();

		$verify_hash = function(){
			return true;
		};

		$get_user_hash = function ($user) {
			return true;
		};

		$ntlm->setVerifyHashMethod($verify_hash);
		$ntlm->setGetUserHashMethod($get_user_hash);
        $this->ntlmObject = $ntlm;
    }

    public function testRemoteIPWithoutRangesLogsIn(){
        $this->ntlmObject->setRemoteIP(new \Bankiru\IPTools\IP("127.0.0.1"));
    	$this->ntlmObject->prompt("testwebsite", "testdomain", "mycomputer", "testdomain.local", "mycomputer.local");
    	$this->assertTrue($this->ntlmObject->is_authenticated);
    }

    public function testRemoteIPOutsideOfRangeDoesntAuthenticate(){
        $this->ntlmObject->setRemoteIP(new \Bankiru\IPTools\IP("127.0.0.1"));
        $testRange = new \Bankiru\IPTools\RangeFactory();
        $testRange = $testRange->parse("192.168.2.*");
        $this->ntlmObject->whitelist->add($testRange);
    	$this->ntlmObject->prompt("testwebsite", "testdomain", "mycomputer", "testdomain.local", "mycomputer.local");
    	$this->assertFalse($this->ntlmObject->is_authenticated);
    }

    public function testRemoteIPInsideOfRangeDoesAuthenticate(){
        $this->ntlmObject->setRemoteIP(new \Bankiru\IPTools\IP("127.0.0.1"));
        $testRange = new \Bankiru\IPTools\RangeFactory();
        $testRange = $testRange->parse("127.0.0.*");
        $this->ntlmObject->whitelist->add($testRange);
    	$this->ntlmObject->prompt("testwebsite", "testdomain", "mycomputer", "testdomain.local", "mycomputer.local");
    	$this->assertTrue($this->ntlmObject->is_authenticated);
    }
}