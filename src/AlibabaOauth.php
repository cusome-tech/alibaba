<?php

namespace alibabasdk;

use alibabasdk\utils\Request;

/**
 * oauth授权
 */
class AlibabaOauth
{
    /**
     * @var string
     */
    protected $oauthUrl = 'https://auth.1688.com/oauth/authorize?client_id=%s&site=1688&redirect_uri=%s&state=%s';

    /**
     * @var string
     */
    protected $tokenUrl = 'https://gw.open.1688.com/openapi/http/1/system.oauth2/getToken/%s';

    /**
     * 授权
     * @param $appKey
     * @param $appSecret
     * @param $redirectUri
     * @param string $state
     * @return array
     * @throws AlibabaException
     */
    public function oauth($appKey, $appSecret, $redirectUri, string $state = 'cross-1688'): array
    {
        $params = $_GET;
        if (!(array_key_exists('code', $params) && $state == $params['state'])) {
            $this->oauthUrl = sprintf($this->oauthUrl, $appKey, urlencode($redirectUri), $state);
            header(sprintf('Location:%s', $this->oauthUrl));
            exit;
        }
        $res = self::accessToken($appKey, $appSecret, $redirectUri, $params['code']);
        $data = json_decode($res, true);
        if (!array_key_exists('access_token', $data)) {
            throw new AlibabaException($data['error_description']);
        }
        return $data;
    }


    /**
     * 构造授权跳转链接
     * @param $appKey
     * @param $redirectUri
     * @param string $state
     * @return string
     */
    public function build($appKey,  $redirectUri, string $state = 'cross-1688')
    {
        return sprintf($this->oauthUrl, $appKey, urlencode($redirectUri), $state);
    }


    /**
     * 获取accessToken
     * @param $appKey
     * @param $appSecret
     * @param $redirect_uri
     * @param $code
     * @return bool|string
     */
    public function accessToken($appKey, $appSecret, $redirectUri, $code)
    {
        $params = [
            'grant_type'         => 'authorization_code',
            'need_refresh_token' => 'true',
            'client_id'          => $appKey,
            'client_secret'      => $appSecret,
            'redirect_uri'       => $redirectUri,
            'code'               => $code
        ];
        return Request::post(sprintf($this->tokenUrl, $appKey), $params);
    }

    /**
     * 刷新accessToken
     * @param $appKey
     * @param $appSecret
     * @param $redirect_uri
     * @param $code
     * @return bool|string
     */
    public function refreshToken($appKey, $appSecret, $refreshToken)
    {
        $params = [
            'grant_type'         => 'refresh_token',
            'need_refresh_token' => 'true',
            'client_id'          => $appKey,
            'client_secret'      => $appSecret,
            'refresh_token'      => $refreshToken,
        ];
        return Request::post(sprintf($this->tokenUrl, $appKey), $params);
    }



}
