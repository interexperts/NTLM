<?php

class NTLMTest extends \PHPUnit_Framework_TestCase {
    public function testStringToMD4(){
        $this->assertEquals(pack("H*", "ef9283d532ca7d2bcb0ea119cef0ec15"), \InterExperts\NTLM\NTLM::toMD4('knownString'));
    }

    public function testShouldBeginTransaction(){
    	$ntlm = $this->getMockBuilder('\InterExperts\NTLM\NTLM')
    	             ->setMethods(array('beginChallenge'))
    	             ->getMock();

    	$ntlm->expects($this->once())
    	     ->method('beginChallenge');

    	$ntlm->prompt("testwebsite", "testdomain", "mycomputer", "testdomain.local", "mycomputer.local");
    }

    /**
     * @runInSeparateProcess
     */
    public function testNotAuthenticatenWhenBeginningTransaction(){
    	$ntlm = new \InterExperts\NTLM\NTLM();
    	$ntlm->prompt("testwebsite", "testdomain", "mycomputer", "testdomain.local", "mycomputer.local");
    	$this->assertFalse($ntlm->is_authenticated);
    }

    public function testShouldAcceptTransactionThenFail(){
    	$_SERVER['HTTP_AUTHORIZATION'] = 'notEmpty';

    	$ntlm = $this->getMockBuilder('\InterExperts\NTLM\NTLM')
    	             ->setMethods(array('clientHasAcceptedChallenge'))
    	             ->getMock();

    	$ntlm->expects($this->once())
    	     ->method('clientHasAcceptedChallenge')
    	     ->will($this->returnValue(TRUE));

    	$this->setExpectedException('Exception', 'NTLM error header not recognised');
        $ntlm->sessionManager->set('_ntlm_post_data', 'test');
    	$ntlm->prompt("testwebsite", "testdomain", "mycomputer", "testdomain.local", "mycomputer.local");
    }

    public function testCanGetHeadersFromApache(){
    	$ntlm = $this->getMockBuilder('\InterExperts\NTLM\NTLM')
    	             ->setMethods(array('beginChallenge', 'canGetHeadersFromApache', 'getApacheHeaders'))
    	             ->getMock();

   		$ntlm->expects($this->once())
    	     ->method('canGetHeadersFromApache')
    	     ->will($this->returnValue(TRUE));

    	$ntlm->expects($this->once())
    	     ->method('getApacheHeaders')
    	     ->will($this->returnValue(array()));

    	$ntlm->expects($this->once())
    	     ->method('beginChallenge');

    	$ntlm->prompt("testwebsite", "testdomain", "mycomputer", "testdomain.local", "mycomputer.local");
    }

    public function testFindPhaseOneIdentifier(){
    	$_SERVER['HTTP_AUTHORIZATION'] = 'NTLM TlRMTVNTUAABAAAAB4IIogAAAAAAAAAAAAAAAAAAAAAGA4AlAAAADw==';

    	$ntlm = $this->getMockBuilder('\InterExperts\NTLM\NTLM')
    	             ->setMethods(array('clientHasAcceptedChallenge', 'isPhaseOneIdentifier', 'sendPhaseTwoHeaders'))
    	             ->getMock();

    	$ntlm->expects($this->once())
    	     ->method('clientHasAcceptedChallenge')
    	     ->will($this->returnValue(TRUE));

    	$ntlm->expects($this->once())
    	     ->method('isPhaseOneIdentifier')
    	     ->will($this->returnValue(TRUE));

    	$ntlm->expects($this->once())
    	     ->method('sendPhaseTwoHeaders');

    	$ntlm->prompt("testwebsite", "testdomain", "mycomputer", "testdomain.local", "mycomputer.local");
    }

    /**
     * @runInSeparateProcess
     */
    public function testNotAuthenticatedWhenSendingPhaseTwoHeaders(){
    	$_SERVER['HTTP_AUTHORIZATION'] = 'NTLM TlRMTVNTUAABAAAAB4IIogAAAAAAAAAAAAAAAAAAAAAGA4AlAAAADw==';

    	$ntlm = $this->getMockBuilder('\InterExperts\NTLM\NTLM')
    	             ->setMethods(array('clientHasAcceptedChallenge'))
    	             ->getMock();

    	$ntlm->expects($this->once())
    	     ->method('clientHasAcceptedChallenge')
    	     ->will($this->returnValue(TRUE));

    	$ntlm->prompt("testwebsite", "testdomain", "mycomputer", "testdomain.local", "mycomputer.local");
    	$this->assertFalse($ntlm->is_authenticated);
    }

    public function testFindPhaseThreeIdentifier(){
    	$_SERVER['HTTP_AUTHORIZATION'] = 'NTLM TlRMTVNTUAADAAAAGAAYAG4AAAASARIBhgAAAAYABgBYAAAACgAKAF4AAAAGAAYAaAAAAAAAAACYAQAABQKAAgYDgCUAAAAP5VQScilF+FdimsHOnQS7fk4AQgBMAGEAZABtAGkAbgBOAEIATAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABPXUvNaz0xMZF9AAySpcl2AQEAAAAAAAB1+1LJ507QAeCrR1SzQl4pAAAAAAIAAAABABQAbQB5AGMAbwBtAHAAdQB0AGUAcgAEACAAdABlAHMAdABkAG8AbQBhAGkAbgAuAGwAbwBjAGEAbAADACAAbQB5AGMAbwBtAHAAdQB0AGUAcgAuAGwAbwBjAGEAbAAIADAAMAAAAAAAAAABAAAAACAAAKZQUgL77gVAvoZTBPma52m1ag8i/CLRhvKkIk0MQSZBCgAQAAAAAAAAAAAAAAAAAAAAAAAJACoASABUAFQAUAAvAG4AdABsAG0ALgBsAGkAYgByAGEAcgB5AC4AZABlAHYAAAAAAAAAAAAAAAAA';

    	$ntlm = $this->getMockBuilder('\InterExperts\NTLM\NTLM')
    	             ->setMethods(array('clientHasAcceptedChallenge', 'isPhaseOneIdentifier', 'isPhaseThreeIdentifier', 'parse_response_msg'))
    	             ->getMock();

    	$ntlm->expects($this->once())
    	     ->method('clientHasAcceptedChallenge')
    	     ->will($this->returnValue(true));

    	$ntlm->expects($this->once())
    	     ->method('isPhaseOneIdentifier')
    	     ->will($this->returnValue(false));

    	$ntlm->expects($this->once())
    	     ->method('isPhaseThreeIdentifier')
    	     ->will($this->returnValue(true));

    	$ntlm->expects($this->once())
    	     ->method('parse_response_msg');
        $ntlm->sessionManager->set('_ntlm_post_data', 'test');
    	$ntlm->prompt("testwebsite", "testdomain", "mycomputer", "testdomain.local", "mycomputer.local");
    }

    /**
     * @runInSeparateProcess
     */
    public function testPhaseThreeLogsIn(){
    	$_SERVER['HTTP_AUTHORIZATION'] = 'NTLM TlRMTVNTUAADAAAAGAAYAG4AAAASARIBhgAAAAYABgBYAAAACgAKAF4AAAAGAAYAaAAAAAAAAACYAQAABQKAAgYDgCUAAAAP5VQScilF+FdimsHOnQS7fk4AQgBMAGEAZABtAGkAbgBOAEIATAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABPXUvNaz0xMZF9AAySpcl2AQEAAAAAAAB1+1LJ507QAeCrR1SzQl4pAAAAAAIAAAABABQAbQB5AGMAbwBtAHAAdQB0AGUAcgAEACAAdABlAHMAdABkAG8AbQBhAGkAbgAuAGwAbwBjAGEAbAADACAAbQB5AGMAbwBtAHAAdQB0AGUAcgAuAGwAbwBjAGEAbAAIADAAMAAAAAAAAAABAAAAACAAAKZQUgL77gVAvoZTBPma52m1ag8i/CLRhvKkIk0MQSZBCgAQAAAAAAAAAAAAAAAAAAAAAAAJACoASABUAFQAUAAvAG4AdABsAG0ALgBsAGkAYgByAGEAcgB5AC4AZABlAHYAAAAAAAAAAAAAAAAA';
    	$ntlm = new \InterExperts\NTLM\NTLM();

		$verify_hash = function(){
			return true;
		};

		$get_user_hash = function ($user) {
			return true;
		};

		$ntlm->setVerifyHashMethod($verify_hash);
		$ntlm->setGetUserHashMethod($get_user_hash);
        $ntlm->sessionManager->set('_ntlm_post_data', 'test');
    	$ntlm->prompt("testwebsite", "testdomain", "mycomputer", "testdomain.local", "mycomputer.local");
    	$this->assertTrue($ntlm->is_authenticated);
    }

    /**
     * @runInSeparateProcess
     */
    public function testPhaseThreeFailsWithBadHashVerification(){
    	$_SERVER['HTTP_AUTHORIZATION'] = 'NTLM TlRMTVNTUAADAAAAGAAYAG4AAAASARIBhgAAAAYABgBYAAAACgAKAF4AAAAGAAYAaAAAAAAAAACYAQAABQKAAgYDgCUAAAAP5VQScilF+FdimsHOnQS7fk4AQgBMAGEAZABtAGkAbgBOAEIATAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABPXUvNaz0xMZF9AAySpcl2AQEAAAAAAAB1+1LJ507QAeCrR1SzQl4pAAAAAAIAAAABABQAbQB5AGMAbwBtAHAAdQB0AGUAcgAEACAAdABlAHMAdABkAG8AbQBhAGkAbgAuAGwAbwBjAGEAbAADACAAbQB5AGMAbwBtAHAAdQB0AGUAcgAuAGwAbwBjAGEAbAAIADAAMAAAAAAAAAABAAAAACAAAKZQUgL77gVAvoZTBPma52m1ag8i/CLRhvKkIk0MQSZBCgAQAAAAAAAAAAAAAAAAAAAAAAAJACoASABUAFQAUAAvAG4AdABsAG0ALgBsAGkAYgByAGEAcgB5AC4AZABlAHYAAAAAAAAAAAAAAAAA';
    	$ntlm = new \InterExperts\NTLM\NTLM();

		$verify_hash = function(){
			return false;
		};

		$get_user_hash = function ($user) {
			return true;
		};

		$ntlm->setVerifyHashMethod($verify_hash);
		$ntlm->setGetUserHashMethod($get_user_hash);
        $ntlm->sessionManager->set('_ntlm_post_data', 'test');
    	$ntlm->prompt("testwebsite", "testdomain", "mycomputer", "testdomain.local", "mycomputer.local");
    	$this->assertFalse($ntlm->is_authenticated);
    }

    public function testPhaseThreeDetectsInvalidNTLM(){
    	$_SERVER['HTTP_AUTHORIZATION'] = 'NTLM TlRMTVNTUAADAAAAGAAYAG4AAAASARIBhgAAAAYABgBYAAAACgAKAF4AAAAGAAYAaAAAAAAAAACYAQAABQKAAgYDgCUAAAAP5VQScilF+FdimsHOnQS7fk4AQgBMAGEAZABtAGkAbgBOAEIATAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABPXUvNazAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA';
    	$ntlm = new \InterExperts\NTLM\NTLM();

		$verify_hash = function(){
			return true;
		};

		$get_user_hash = function ($user) {
			return true;
		};

		$ntlm->setVerifyHashMethod($verify_hash);
		$ntlm->setGetUserHashMethod($get_user_hash);
        $ntlm->sessionManager->set('_ntlm_post_data', 'test');
    	$ntlm->prompt("testwebsite", "testdomain", "mycomputer", "testdomain.local", "mycomputer.local");
    	$this->assertFalse($ntlm->is_authenticated);
    }

    public function testPhaseThreeDefaultHashVerification(){
    	$_SERVER['HTTP_AUTHORIZATION'] = 'NTLM TlRMTVNTUAADAAAAGAAYAG4AAAASARIBhgAAAAYABgBYAAAACgAKAF4AAAAGAAYAaAAAAAAAAACYAQAABQKAAgYDgCUAAAAP5VQScilF+FdimsHOnQS7fk4AQgBMAGEAZABtAGkAbgBOAEIATAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABPXUvNaz0xMZF9AAySpcl2AQEAAAAAAAB1+1LJ507QAeCrR1SzQl4pAAAAAAIAAAABABQAbQB5AGMAbwBtAHAAdQB0AGUAcgAEACAAdABlAHMAdABkAG8AbQBhAGkAbgAuAGwAbwBjAGEAbAADACAAbQB5AGMAbwBtAHAAdQB0AGUAcgAuAGwAbwBjAGEAbAAIADAAMAAAAAAAAAABAAAAACAAAKZQUgL77gVAvoZTBPma52m1ag8i/CLRhvKkIk0MQSZBCgAQAAAAAAAAAAAAAAAAAAAAAAAJACoASABUAFQAUAAvAG4AdABsAG0ALgBsAGkAYgByAGEAcgB5AC4AZABlAHYAAAAAAAAAAAAAAAAA';

    	$ntlm = new \InterExperts\NTLM\NTLM();
		$get_user_hash = function ($user) {
			return true;
		};

		$ntlm->setGetUserHashMethod($get_user_hash);
        $ntlm->sessionManager->set('_ntlm_post_data', 'test');
    	$ntlm->prompt("testwebsite", "testdomain", "mycomputer", "testdomain.local", "mycomputer.local");
    	$this->assertFalse($ntlm->is_authenticated);
    }

    public function testPhaseThreeDefaultWontLogInWithWrongGetHashFunction(){
    	$_SERVER['HTTP_AUTHORIZATION'] = 'NTLM TlRMTVNTUAADAAAAGAAYAG4AAAASARIBhgAAAAYABgBYAAAACgAKAF4AAAAGAAYAaAAAAAAAAACYAQAABQKAAgYDgCUAAAAP5VQScilF+FdimsHOnQS7fk4AQgBMAGEAZABtAGkAbgBOAEIATAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABPXUvNaz0xMZF9AAySpcl2AQEAAAAAAAB1+1LJ507QAeCrR1SzQl4pAAAAAAIAAAABABQAbQB5AGMAbwBtAHAAdQB0AGUAcgAEACAAdABlAHMAdABkAG8AbQBhAGkAbgAuAGwAbwBjAGEAbAADACAAbQB5AGMAbwBtAHAAdQB0AGUAcgAuAGwAbwBjAGEAbAAIADAAMAAAAAAAAAABAAAAACAAAKZQUgL77gVAvoZTBPma52m1ag8i/CLRhvKkIk0MQSZBCgAQAAAAAAAAAAAAAAAAAAAAAAAJACoASABUAFQAUAAvAG4AdABsAG0ALgBsAGkAYgByAGEAcgB5AC4AZABlAHYAAAAAAAAAAAAAAAAA';

    	$ntlm = new \InterExperts\NTLM\NTLM();
		$get_user_hash = function ($user) {
			return false;
		};

		$ntlm->setGetUserHashMethod($get_user_hash);
        $ntlm->sessionManager->set('_ntlm_post_data', 'test');
    	$ntlm->prompt("testwebsite", "testdomain", "mycomputer", "testdomain.local", "mycomputer.local");
    	$this->assertFalse($ntlm->is_authenticated);
    }

	public function testHMACWithShortKey(){
    	$_SERVER['HTTP_AUTHORIZATION'] = 'NTLM TlRMTVNTUAADAAAAGAAYAG4AAAASARIBhgAAAAYABgBYAAAACgAKAF4AAAAGAAYAaAAAAAAAAACYAQAABQKAAgYDgCUAAAAP5VQScilF+FdimsHOnQS7fk4AQgBMAGEAZABtAGkAbgBOAEIATAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABPXUvNaz0xMZF9AAySpcl2AQEAAAAAAAB1+1LJ507QAeCrR1SzQl4pAAAAAAIAAAABABQAbQB5AGMAbwBtAHAAdQB0AGUAcgAEACAAdABlAHMAdABkAG8AbQBhAGkAbgAuAGwAbwBjAGEAbAADACAAbQB5AGMAbwBtAHAAdQB0AGUAcgAuAGwAbwBjAGEAbAAIADAAMAAAAAAAAAABAAAAACAAAKZQUgL77gVAvoZTBPma52m1ag8i/CLRhvKkIk0MQSZBCgAQAAAAAAAAAAAAAAAAAAAAAAAJACoASABUAFQAUAAvAG4AdABsAG0ALgBsAGkAYgByAGEAcgB5AC4AZABlAHYAAAAAAAAAAAAAAAAA';

    	$ntlm = new \InterExperts\NTLM\NTLM();
		$get_user_hash = function ($user) {
			return '1234567890123456789012345678901234567890123456789012345678901234567890';
		};

		$ntlm->setGetUserHashMethod($get_user_hash);
        $ntlm->sessionManager->set('_ntlm_post_data', 'test');
    	$ntlm->prompt("testwebsite", "testdomain", "mycomputer", "testdomain.local", "mycomputer.local");
    	$this->assertFalse($ntlm->is_authenticated);
    }

    public function testDefaultGetHash(){
    	$_SERVER['HTTP_AUTHORIZATION'] = 'NTLM TlRMTVNTUAADAAAAGAAYAG4AAAASARIBhgAAAAYABgBYAAAACgAKAF4AAAAGAAYAaAAAAAAAAACYAQAABQKAAgYDgCUAAAAP5VQScilF+FdimsHOnQS7fk4AQgBMAGEAZABtAGkAbgBOAEIATAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABPXUvNaz0xMZF9AAySpcl2AQEAAAAAAAB1+1LJ507QAeCrR1SzQl4pAAAAAAIAAAABABQAbQB5AGMAbwBtAHAAdQB0AGUAcgAEACAAdABlAHMAdABkAG8AbQBhAGkAbgAuAGwAbwBjAGEAbAADACAAbQB5AGMAbwBtAHAAdQB0AGUAcgAuAGwAbwBjAGEAbAAIADAAMAAAAAAAAAABAAAAACAAAKZQUgL77gVAvoZTBPma52m1ag8i/CLRhvKkIk0MQSZBCgAQAAAAAAAAAAAAAAAAAAAAAAAJACoASABUAFQAUAAvAG4AdABsAG0ALgBsAGkAYgByAGEAcgB5AC4AZABlAHYAAAAAAAAAAAAAAAAA';

    	$ntlm = new \InterExperts\NTLM\NTLM();
        $ntlm->sessionManager->set('_ntlm_post_data', 'test');
    	$ntlm->prompt("testwebsite", "testdomain", "mycomputer", "testdomain.local", "mycomputer.local");
    	$this->assertFalse($ntlm->is_authenticated);
    }

    public function testDefaultGetHashWrongUsername(){
    	$_SERVER['HTTP_AUTHORIZATION'] = 'NTLM TlRMTVNTUAADAAAAGAAYAG4AAAASARIBhgAAAAYABgBYAAAACgAKaa4AAAAGAAYAaAAAAAAAAACYAQAABQKAAgYDgCUAAAAP5VQScilF+FdimsHOnQS7fk4AQgBMAGEAZABtAGkAbgBOAEIATAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABPXUvNaz0xMZF9AAySpcl2AQEAAAAAAAB1+1LJ507QAeCrR1SzQl4pAAAAAAIAAAABABQAbQB5AGMAbwBtAHAAdQB0AGUAcgAEACAAdABlAHMAdABkAG8AbQBhAGkAbgAuAGwAbwBjAGEAbAADACAAbQB5AGMAbwBtAHAAdQB0AGUAcgAuAGwAbwBjAGEAbAAIADAAMAAAAAAAAAABAAAAACAAAKZQUgL77gVAvoZTBPma52m1ag8i/CLRhvKkIk0MQSZBCgAQAAAAAAAAAAAAAAAAAAAAAAAJACoASABUAFQAUAAvAG4AdABsAG0ALgBsAGkAYgByAGEAcgB5AC4AZABlAHYAAAAAAAAAAAAAAAAA';
    	$ntlm = new \InterExperts\NTLM\NTLM();
        $ntlm->sessionManager->set('_ntlm_post_data', 'test');
    	$ntlm->prompt("testwebsite", "testdomain", "mycomputer", "testdomain.local", "mycomputer.local");
    	$this->assertFalse($ntlm->is_authenticated);
    }

    public function testReturnsIfAlreadyLoggedIn(){
    	$ntlm = $this->getMockBuilder('\InterExperts\NTLM\NTLM')
    	             ->setMethods(array('isAlreadyAuthenticated'))
    	             ->getMock();

    	$ntlm->expects($this->once())
    	     ->method('isAlreadyAuthenticated')
    	     ->will($this->returnValue(true));

        $ntlm->sessionManager->set('_ntlm_auth', 'test');
    	$this->assertEquals('test', $ntlm->prompt("testwebsite", "testdomain", "mycomputer", "testdomain.local", "mycomputer.local"));
    }

    public function testCanLogOut(){
    	$ntlm = new \InterExperts\NTLM\NTLM();
    	$ntlm->sessionManager->set('_ntlm_auth', 'test');
    	$ntlm->ntlm_unset_auth();
    	$this->assertFalse(isset($_SESSION['_ntlm_auth']));
    }
}