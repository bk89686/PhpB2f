<?php

namespace Blue2Factor\Authentication;
require __DIR__ . '/../../vendor/autoload.php';

use Exception;

use Firebase\JWT\Key;
use Firebase\JWT\SignatureInvalidException;
use Firebase\JWT\BeforeValidException;
use Firebase\JWT\ExpiredException;
use Firebase\JWT\JWT;

class blue2factor {
    
    private $secureUrl = "https://secure.blue2factor.com";
    private $sender = "";
    private $SUCCESS = 0;
    private $FAILURE = 1;
    private $EXPIRED = -1;
    private $setup = null;
    private $b2fCookie = null;
    private $redirect = null;
    
    public function getRedirect(){
        return $this->redirect;
    }
    
    public function getCookie(){
        return $this->b2fCookie;
    }
    
    public function getSetup(){
        return $this->setup;
    }
    
    private function getEndpoint($companyId) {
        return "{$this->secureUrl}/SAML2/SSO/{$companyId}/Token";
    }
    
    private function getFailureUrl($companyId) {
        return "{$this->secureUrl}/failure/{$companyId}/recheck";
    }
    
    private function getResetUrl($companyId) {
        return "{$this->secureUrl}/failure/{$companyId}/reset";
    }
    
    private function getIssuer($companyId) {
        return "{$this->secureUrl}/SAML2/SSO/{$companyId}/EntityId";
    }
    
    private function getSignout($companyId) {
        return $this->redirectTo("{$this->secureUrl}/SAML2/SSO/{$companyId}/Signout");
    }
    
    function getB2fCookie(){
        $cook = "";
        if(!isset($_COOKIE["B2F_AUTH"])) {
            $cook = $_COOKIE["B2F_AUTH"];
        }
        return $cook;
    }
    
    function authenticateRequest($companyId, $loginUrl, $privateKeyStr){
        $jwt = $_POST['name'];
        if ($jwt == null) {
            $jwt = $this->getB2fCookie();
        }
        $b2fSetup = $_POST['b2fSetup'];
        $url = $this->getCurrentUrl();
        [$auth, $currCookie, $reject, $currSetup] = $this->authenticate($url, $jwt, $companyId,
            $loginUrl, $b2fSetup, $privateKeyStr);
        $this->redirect = $reject; //this needs to actually redirect
        $this->b2fCookie = $currCookie;
        $this->setup = $currSetup;
        if ($this->redirect != null) {
            $this->redirectTo($this->redirect);
        }
        return $auth;
    }
    
    function redirectTo($url){
        if (headers_sent() === false) {
            header("Location: {$url}", true, 302);
        }
        exit();
    }
    
    private function getCurrentUrl(){
        $protocol = ((!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] != 'off') ||
            $_SERVER['SERVER_PORT'] == 443) ? "https://" : "http://";
            return $protocol.$_SERVER['HTTP_HOST'].$_SERVER['REQUEST_URI'];
    }
    
    function authenticate($url, $jwt, $companyId, $loginUrl, $b2fSetup, $privateKeyStr){
        if ($jwt != null) {
            [$success, $newToken] = $this->b2fAuthorized($jwt, $companyId, $loginUrl, $privateKeyStr);
            if ($success) {
                return [true, $newToken, null, $b2fSetup];
            } else {
                $url = $url.explode("?", $url)[0];
                return [false, $newToken, "{$this->getFailureUrl($companyId)}?url={urlencode($url)}", $b2fSetup];
            }
        } else {
            $this->b2fLog(LOG_INFO, "jwt was null");
            $redirectSite = "{$this->getResetUrl($companyId)}?url={urldecode(url)}";
            $this->b2fLog(LOG_DEBUG, "setting return url to {$redirectSite}");
            setB2fCookie();
            return [false, "", $redirectSite, $b2fSetup];
        }
    }
    
    private function b2fAuthorized($jwt, $companyId, $loginUrl, $privateKeyStr){
        $success = false;
        $newToken = null;
        try {
            $outcome = $this->tokenIsValid($jwt, $companyId, $loginUrl);
            if ($outcome == $this->SUCCESS) {
                $this->b2fLog(LOG_INFO, "token was valid");
                $newToken = $jwt;
                $success = true;
            } else {
                if ($outcome == $this->EXPIRED){
                    $this->b2fLog(LOG_INFO, "token was not valid, will attempt to get new one");
                    [$success, $newToken] = $this->getNewToken($jwt, $companyId, $loginUrl, $privateKeyStr);
                }
            }
        } catch (Exception $e) {
            $this->b2fLog(LOG_AUTH, $e->getMessage());
        }
        return [$success, $newToken];
    }
    
    private function tokenIsValid($jwt, $companyId, $loginUrl) {
        $outcome = $this->FAILURE;
        if ($this->notEmpty($jwt)) {
            $this->b2fLog(LOG_DEBUG, "jwt: {$jwt}");
            $url = $this->getUrlFromJwtHeader($jwt);
            $publicKey = $this->getPublicKeyFromUrl($url);
            if ($this->notEmpty($publicKey)) {
                try {
                    $key = new Key($publicKey, 'RS256');
                    $this->b2fLog(LOG_DEBUG, "key was loaded");
                    $decoded = JWT::decode($jwt, $key);
                    $this->b2fLog(LOG_DEBUG, "key was decoded");
                    $decodedArr = (array) $decoded;
                    if ($decodedArr["aud"] == $loginUrl) {
                        $this->b2fLog(LOG_DEBUG, "loginUrl was correct");
                        if ($decodedArr["iss"] == $this->getIssuer($companyId)) {
                            $this->b2fLog(LOG_DEBUG, "issuer was correct");
                            $outcome = $this->SUCCESS;
                        } else {
                            $this->b2fLog(LOG_DEBUG, "issuer was incorrect");
                        }
                    } else {
                        $this->b2fLog(LOG_DEBUG, "loginUrl was incorrect");
                    }
                } catch (SignatureInvalidException $e0) {
                    $this->b2fLog(LOG_AUTH, $e0->getMessage());
                } catch (BeforeValidException $e1) {
                    $this->b2fLog(LOG_AUTH, $e1->getMessage());
                } catch (ExpiredException $e2) {
                    $this->b2fLog(LOG_AUTH, $e2->getMessage());
                    $outcome = $this->EXPIRED;
                } catch (Exception $e3) {
                    $this->b2fLog(LOG_AUTH, $e3->getMessage());
                }
            }
        } else {
            $this->b2fLog(LOG_ERR, "token was empty");
        }
        return $outcome;
    }
    
    private function getUrlFromJwtHeader($jwt) {
        $url = null;
        try {
            $header = urldecode(explode(".", $jwt)[0]);
            $decoded = base64_decode($header, true);
            $json = json_decode($decoded, true);
            $url = $json["x5u"];
            $this->b2fLog(LOG_INFO, "url = {$url}");
        } catch (Exception $e) {
            log_exception($e);
        }
        return $url;
    }
    
    private function getNewToken($jwt, $companyId, $loginUrl, $privateKeyStr) {
        $success = false;
        $newJwt = null;
        try {
            $signature = $this->getSignature($jwt, $privateKeyStr);
            $url = $this->getEndpoint($companyId);
            $this->b2fLog(LOG_INFO, "checking {$url}");
            $curl = curl_init($url);
            curl_setopt($curl, CURLOPT_URL, $url);
            curl_setopt($curl, CURLOPT_RETURNTRANSFER, true);
            $headers = array(
                "Accept: application/json",
                "Authorization: Bearer {$jwt}&{$signature}",
            );
            curl_setopt($curl, CURLOPT_HTTPHEADER, $headers);
            $result = curl_exec($curl);
            $httpStatus = curl_getinfo($curl, CURLINFO_HTTP_CODE);
            if ($httpStatus == 200) {
                $json = json_decode($result, true);
                if ($json["outcome"] == $this->SUCCESS){
                    $newJwt = $json["token"];
                    $success = tokenIsValid($jwt, $companyId, $loginUrl) == $this->SUCCESS;
                }
            }
            curl_close($curl);
            var_dump($result);
        } catch (Exception $e) {
            log_exception($e);
        }
        return [$success, $newJwt];
    }
    
    private function getSignature($jwt, $privateKeyStr) {
        $pemHeader = "-----BEGIN RSA PRIVATE KEY-----";
        $pemFooter = "-----END RSA PRIVATE KEY-----";
        $privateKeyStr = str_replace($pemHeader, "", $privateKeyStr);
        $privateKeyStr = str_replace($pemFooter, "", $privateKeyStr);
        $privateKeyStr = str_replace("\n", "", $privateKeyStr);
        $privateKeyStr = str_replace("\r", "", $privateKeyStr);
        $privateKeyStr = $this->addNewLinesToString($privateKeyStr);
        $privateKey = "{$pemHeader}\n{$privateKeyStr}{$pemFooter}";
        openssl_sign($jwt, $signature, $privateKey, OPENSSL_ALGO_SHA256);
        $encoded = base64_encode($signature);
        return $encoded;
    }
    
    private function notEmpty($var) {
        return $var != null && $var != "";
    }
    
    private function getPublicKeyFromUrl($url) {
        $publicKey = null;
        if ($this->notEmpty($url)) {
            try {
                $curl = curl_init($url);
                curl_setopt($curl, CURLOPT_URL, $url);
                curl_setopt($curl, CURLOPT_RETURNTRANSFER, true);
                $result = curl_exec($curl);
                $httpStatus = curl_getinfo($curl, CURLINFO_HTTP_CODE);
                if ($httpStatus == 200) {
                    $publicKey = ("-----BEGIN PUBLIC KEY-----\n{$this->addNewLinesToString($result)}-----END PUBLIC KEY-----");
                }
                $this->b2fLog(LOG_DEBUG, "retrievedKey:\n{$publicKey}\n\n");
            } catch (Exception $e) {
                log_exception($e);
            }
        } else {
            $this->b2fLog(LOG_ALERT, "url was empty from header");
        }
        return $publicKey;
    }
    
    private function addNewLinesToString($text){
        $len = strlen($text);
        $i = 0;
        $newText = "";
        while ($i < ($len/64) + 1) {
            $sub = substr($text, $i*64, 64);
            if (strlen($sub) > 0) {
                $newText = "{$newText}{$sub}\n";
            }
            $i = $i + 1;
        }
        $this->b2fLog(LOG_DEBUG, $newText);
        return $newText;
    }
    
    
    
    
    private function setB2fCookie() {
        if ($this->setup != null) {
            setcookie("b2fSetup", $this->setup, time() + (60 * 60), "/", null, true);
        }
        if ($this->b2fCookie != null) {
            setcookie("B2F_AUTH", $this->b2fCookie, time() + (86400 * 90), "/", null, true);
        }
    }
    
    public function b2fLog (int $priority, string $str) {
        try {
            syslog($priority, $str);
            //             echo $str;
            //             echo "\n";
        } catch (Exception $e) {
            log_exception($e);
        }
    }
    
    public function log (string $str) {
        $this->b2fLog(LOG_DEBUG, $str);
    }
}
?>
