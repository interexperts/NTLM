<?php

// Report all PHP errors (see changelog)
error_reporting(E_ALL);
ini_set('display_errors', '1');

require_once("NTLM.php");
require_once("NTLMUser.php");

$ntlm = new InterExperts\NTLM\NTLM();

var_dump($ntlm);

$verify_hash = function(){
	return true;
};

$get_user_hash = function ($user) {
	$userdb = array('loune'=>'test', 'user1'=>'password');
	if (!isset($userdb[strtolower($user)])){
		return false;	
	}
	return InterExperts\NTLM\NTLM::toMD4(InterExperts\NTLM\NTLM::UTF8ToUTF16le($userdb[strtolower($user)]));
};

session_start();
//$ntlm->setVerifyHashMethod($verify_hash);
//$ntlm->setGetUserHashMethod($get_user_hash);

$auth = $ntlm->prompt("testwebsite", "testdomain", "mycomputer", "testdomain.local", "mycomputer.local");

if ($ntlm->is_authenticated) {
	print "You are authenticated as {$ntlm->user->username} from {$ntlm->user->domain}/{$ntlm->user->workstation}";
}

var_dump($ntlm);

$ntlm->ntlm_unset_auth();