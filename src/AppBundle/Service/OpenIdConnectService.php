<?php

namespace AppBundle\Service;

class OpenIdConnectService
{
    public function getToken($code)
    {
        // post
        $postData = array(
            'code' => $code,
            'client_id' => 'xxxxxxx.apps.googleusercontent.com',
            'client_secret' => 'xxxxxx',
            'redirect_uri' => 'http://localhost/app_dev.php/google',
            'grant_type' => 'authorization_code'
        );

        $curlOpts = array(
            CURLOPT_URL => "https://www.googleapis.com/oauth2/v4/token",
            CURLOPT_HEADER => array("Content-type: application/x-www-form-urlencoded"),
            CURLOPT_POST => true,
            CURLOPT_POSTFIELDS => http_build_query($postData),
            CURLOPT_RETURNTRANSFER => true
        );

        $ch = curl_init();
        curl_setopt_array($ch, $curlOpts);
        $response = curl_exec($ch);
        $headerSize = curl_getinfo($ch, CURLINFO_HEADER_SIZE);
        $body = substr($response, $headerSize);
        curl_close($ch);

        return json_decode($body, true);
    }

    public function getCerts()
    {
        // get
        $curlGetOptions = array(
            CURLOPT_URL => "https://www.googleapis.com/oauth2/v1/certs",
            CURLOPT_HEADER => true,
            CURLOPT_RETURNTRANSFER => true
        );

        $curlCh = curl_init();
        curl_setopt_array($curlCh, $curlGetOptions);
        $keysResponse = curl_exec($curlCh);
        $keysHeaderSize = curl_getinfo($curlCh, CURLINFO_HEADER_SIZE);
        $cBody = substr($keysResponse, $keysHeaderSize);
        curl_close($curlCh);

        // 検証
        return json_decode($cBody, true);
    }
}