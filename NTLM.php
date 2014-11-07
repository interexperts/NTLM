<?php
namespace InterExperts\NTLM;

// loune 25/3/2006, 22/08/2009, 20/09/2009
// For more information see:
// http://siphon9.net/loune/2009/09/ntlm-authentication-in-php-now-with-ntlmv2-hash-checking/
//

/*

php ntlm authentication library
Version 1.2

Copyright (c) 2009-2010 Loune Lam

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE.

Usage:

	include('ntlm.php');

	function get_ntlm_user_hash($user) {
		$userdb = array('loune'=>'test', 'user1'=>'password');
		
		if (!isset($userdb[strtolower($user)]))
			return false;	
		return ntlm_md4(ntlm_utf8_to_utf16le($userdb[strtolower($user)]));
	}

	session_start();
	$auth = ntlm_prompt("testwebsite", "testdomain", "mycomputer", "testdomain.local", "mycomputer.local", "get_ntlm_user_hash");

	if ($auth['authenticated']) {
		print "You are authenticated as $auth[username] from $auth[domain]/$auth[workstation]";
	}

To logout, use the code:

	ntlm_unset_auth();
	
SAMBA
-----	
To use this library with samba, please read the instructions inside verifyntlm.c 
to compile the verifyntlm helper. Use the ntlm.php library as above but omit the
get_ntlm_user_hash function and replace the ntlm_prompt line with this one:

	$auth = ntlm_prompt("testwebsite", "testdomain", "mycomputer", "testdomain.local", "mycomputer.local", null, "ntlm_verify_hash_smb");
	
For more, see http://siphon9.net/loune/2010/12/php-ntlm-integration-with-samba/

*/

class NTLM{
	protected $verifyHash = null;
	protected $getUserHash = null;
	public $is_authenticated = false;
	public $error = null;
	public $user = null;

	public function __construct(){
		$this->verifyHash = function($challenge, $user, $domain, $workstation, $clientblobhash, $clientblob) {
			$md4hash = call_user_func($this->getUserHash, $user);
			if (!$md4hash){
				return false;
			}
			$ntlmv2hash = $this->hmac_md5($md4hash, self::UTF8ToUTF16le(strtoupper($user).$domain));
			$blobhash = $this->hmac_md5($ntlmv2hash, $challenge.$clientblob);
			
			return ($blobhash == $clientblobhash);
		};

		$this->getUserHash = function ($user) {
			$userdb = array('admin'=>'admin');
			if (!isset($userdb[strtolower($user)])){
				return false;	
			}
			return self::toMD4(self::UTF8ToUTF16le($userdb[strtolower($user)]));
		};
	}

	public function setVerifyHashMethod(callable $hashVerification){
		$this->verifyHash = $hashVerification;
		return $this;
	}

	public function setGetUserHashMethod(callable $getUserHash){
		$this->getUserHash = $getUserHash;
		return $this;
	}

	public static function UTF8ToUTF16le($str) {
		return iconv('UTF-8', 'UTF-16LE', $str);
	}

	public static function toMD4($s) {
		return pack('H*', hash('md4', $s));
	}	

	protected function av_pair($type, $utf16) {
		return pack('v', $type).pack('v', strlen($utf16)).$utf16;
	}

	protected function field_value($msg, $start, $decode_utf16 = true) {
		$len = (ord($msg[$start+1]) * 256) + ord($msg[$start]);
		$off = (ord($msg[$start+5]) * 256) + ord($msg[$start+4]);
		$result = substr($msg, $off, $len);
		if ($decode_utf16) {
			$result = iconv('UTF-16LE', 'UTF-8', $result);
		}
		return $result;
	}

	protected function hmac_md5($key, $msg) {
		$blocksize = 64;
		if (strlen($key) > $blocksize){
			$key = pack('H*', md5($key));
		}
		
		$key = str_pad($key, $blocksize, "\0");
		$ipadk = $key ^ str_repeat("\x36", $blocksize);
		$opadk = $key ^ str_repeat("\x5c", $blocksize);
		return pack('H*', md5($opadk.pack('H*', md5($ipadk.$msg))));
	}

	protected function get_random_bytes($length) {
		$result = "";
		for ($i = 0; $i < $length; $i++) {
			$result .= chr(rand(0, 255));
		}
		return $result;
	}

	protected function get_challenge_msg($msg, $challenge, $targetname, $domain, $computer, $dnsdomain, $dnscomputer) {
		$domain = $this->field_value($msg, 16);
		$ws = $this->field_value($msg, 24);
		$tdata = $this->av_pair(2, self::UTF8ToUTF16le($domain)).$this->av_pair(1, self::UTF8ToUTF16le($computer)).$this->av_pair(4, self::UTF8ToUTF16le($dnsdomain)).$this->av_pair(3, self::UTF8ToUTF16le($dnscomputer))."\0\0\0\0\0\0\0\0";
		$tname = self::UTF8ToUTF16le($targetname);

		$msg2 = "NTLMSSP\x00\x02\x00\x00\x00".
			pack('vvV', strlen($tname), strlen($tname), 48). // target name len/alloc/offset
			"\x01\x02\x81\x00". // flags
			$challenge. // challenge
			"\x00\x00\x00\x00\x00\x00\x00\x00". // context
			pack('vvV', strlen($tdata), strlen($tdata), 48 + strlen($tname)). // target info len/alloc/offset
			$tname.$tdata;
		return $msg2;
	}

	protected function parse_response_msg($msg, $challenge) {
		$user = $this->field_value($msg, 36);
		$domain = $this->field_value($msg, 28);
		$workstation = $this->field_value($msg, 44);
		$ntlmresponse = $this->field_value($msg, 20, false);
		$clientblob = substr($ntlmresponse, 16);
		$clientblobhash = substr($ntlmresponse, 0, 16);

		if (substr($clientblob, 0, 8) != "\x01\x01\x00\x00\x00\x00\x00\x00") {
			$this->is_authenticated = false;
			$this->error = 'NTLMv2 response required. Please force your client to use NTLMv2.';
			return $this;
		}
		
		$verified_hash = call_user_func($this->verifyHash, $challenge, $user, $domain, $workstation, $clientblobhash, $clientblob);

		if (!$verified_hash){
			$this->is_authenticated = false;
			$this->error = 'Incorrect username or password.';
			$this->user = new NTLMUser($user, $domain, $workstation);
			return $this;
		}
		$this->is_authenticated = true;
		$this->error = null;
		$this->user = new NTLMUser($user, $domain, $workstation);
		return $this;
	}

	public function ntlm_unset_auth() {
		unset ($_SESSION['_ntlm_auth']);
	}

	public function prompt($targetname, $domain, $computer, $dnsdomain, $dnscomputer, $failmsg = "<h1>Authentication Required</h1>") {
		$auth_header = isset($_SERVER['HTTP_AUTHORIZATION']) ? $_SERVER['HTTP_AUTHORIZATION'] : null;
		if ($auth_header == null && function_exists('apache_request_headers')) {
			$headers = apache_request_headers();
			$auth_header = isset($headers['Authorization']) ? $headers['Authorization'] : null;
		}
		
		if (isset($_SESSION['_ntlm_auth']))
			return $_SESSION['_ntlm_auth'];
		
		if (!$auth_header) {
			header('HTTP/1.1 401 Unauthorized');
			header('WWW-Authenticate: NTLM');
			$this->defaultLoginError($failmsg);
		}
		if (substr($auth_header,0,5) == 'NTLM ') {
			$msg = base64_decode(substr($auth_header, 5));
			if (substr($msg, 0, 8) != "NTLMSSP\x00") {
				unset($_SESSION['_ntlm_post_data']);
				throw new Exception('NTLM error header not recognised');
			}

			if ($msg[8] == "\x01") {
				$_SESSION['_ntlm_server_challenge'] = $this->get_random_bytes(8);
				header('HTTP/1.1 401 Unauthorized');
				$msg2 = $this->get_challenge_msg($msg, $_SESSION['_ntlm_server_challenge'], $targetname, $domain, $computer, $dnsdomain, $dnscomputer);
				header('WWW-Authenticate: NTLM '.trim(base64_encode($msg2)));
				$this->defaultLoginError($failmsg);
			}elseif ($msg[8] == "\x03") {
				$this->parse_response_msg($msg, $_SESSION['_ntlm_server_challenge']);
				unset($_SESSION['_ntlm_server_challenge']);
				
				if (!$this->is_authenticated) {
					$this->defaultLoginError($this->error);
				}
				
				$_SESSION['_ntlm_auth'] = $this;
				return $this;
			}
		}
	}

	protected function defaultLoginError($message = null){
		if(!isset($message)){
			$message = "<h1>Unable to log in!</h1>";
		}
		$this->is_authenticated = false;
		$this->error = $message;
	}
}

?>
