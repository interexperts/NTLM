<?php
namespace InterExperts\NTLM;

class SessionManager{
    public function get($key){
        if(isset($_SESSION[$key])){
            return  $_SESSION[$key];
        }
        return null;
    }

    public function set($key, $value = null){
        $_SESSION[$key] = $value;
    }
}