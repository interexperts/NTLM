<?php

namespace InterExperts\NTLM;

use \Bankiru\IPTools;

class IPWhitelist{
    public $whitelist = array();

    public function isValidIP(IPTools\IP $remoteIP){
        foreach($this->whitelist as $range){
            if($range->includesIP($remoteIP)){
                return true;
            }
        }
        return false;
    }

    public function hasAccess(IPTools\IP $remoteIP){
        if(!$this->isActive()){
            return true;
        }
        return $this->isValidIP($remoteIP);
    }

    public function add(IPTools\Range $range){
        array_unshift($this->whitelist, $range);
    }

    public function isActive(){
        return count($this->whitelist) > 0;
    }
}