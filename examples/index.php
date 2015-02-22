<?php
error_reporting(E_ALL);
ini_set('display_errors', '1');

require_once(dirname(__FILE__). "/../vendor/autoload.php");

use InterExperts\NTLM\NTLM;

$ntlm = new NTLM();

$get_user_hash = function ($user) {
	$userdb = array('user1'=>'examplePassword', 'user2'=>'aDifferentPassword');
	if (!isset($userdb[strtolower($user)])){
		return false;	
	}
	return NTLM::toMD4(NTLM::UTF8ToUTF16le($userdb[strtolower($user)]));
};

session_start();
//$ntlm->setVerifyHashMethod($verify_hash);
$ntlm->setGetUserHashMethod($get_user_hash);

$auth = $ntlm->prompt("testwebsite", "testdomain", "mycomputer", "testdomain.local", "mycomputer.local");

if ($ntlm->is_authenticated) {
	print "You are authenticated as user `{$ntlm->user->username}` from `{$ntlm->user->domain}/{$ntlm->user->workstation}`.";
}else{
	print "You are not authenticated.";
}

$ntlm->ntlm_unset_auth();