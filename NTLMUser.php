<?php
namespace InterExperts\NTLM;

class NTLMUser{
	public $username    = '';
	public $domain      = '';
	public $workstation = '';

	public function __construct($username, $domain, $workstation){
		$this->username    = $username;
		$this->domain      = $domain;
		$this->workstation = $workstation;
	}
}