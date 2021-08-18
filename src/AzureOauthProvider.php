<?php

namespace Metrogistics\AzureSocialite;

use Illuminate\Support\Arr;
use Laravel\Socialite\Two\User;
use Laravel\Socialite\Two\AbstractProvider;
use Laravel\Socialite\Two\ProviderInterface;
use Laravel\Socialite\Two\InvalidStateException;

class AzureOauthProvider extends AbstractProvider implements ProviderInterface
{
    const IDENTIFIER = 'AZURE_OAUTH';
    protected $scopes = ['User.Read', 'openid', 'profile', 'email'];
    protected $scopeSeparator = ' ';

    protected function getAuthUrl($state)
    {
        return $this->buildAuthUrlFromBase('https://login.microsoftonline.com/common/oauth2/v2.0/authorize', $state);
    }

    protected function getTokenUrl()
    {
        return 'https://login.microsoftonline.com/common/oauth2/v2.0/token';
    }

    protected function getTokenFields($code)
    {
        return array_merge(parent::getTokenFields($code), [
            'grant_type' => 'authorization_code',
        ]);
    }

    protected function getUserByToken($token)
    {
        $response = $this->getHttpClient()->get('https://graph.microsoft.com/v1.0/me/', [
            'headers' => [
                'Authorization' => 'Bearer '.$token,
            ],
        ]);

        return json_decode($response->getBody(), true);
    }

    public function user()
    {
//        if ($this->hasInvalidState()) {
//         //   return $this->request->session();
//            return $this->request->session()->pull('state') . '           ||           ' . $this->request->input('state');
//            throw new InvalidStateException;
//        }

        $response = $this->getAccessTokenResponse($this->getCode());

        $user = $this->mapUserToObject($this->getUserByToken(
            $token = Arr::get($response, 'access_token')
        ));

        $user->idToken = Arr::get($response, 'id_token');
        $user->expiresAt = time() + Arr::get($response, 'expires_in');

        return $user->setToken($token)
                    ->setRefreshToken(Arr::get($response, 'refresh_token'));
    }

    protected function mapUserToObject(array $user)
    {
        return (new User())->setRaw($user)->map([
            'id'                => $user['id'],
            'name'              => array_key_exists('displayName', $user) ? $user['displayName'] : (array_key_exists('givenName', $user) ? $user['givenName'] : 'Unknown'),
            'email'             => $user['email'] ?? $user['mail'] ,

            'businessPhones'    => array_key_exists('businessPhones', $user) ? $user['businessPhones'] : '',
            'displayName'       => array_key_exists('displayName', $user) ? $user['displayName'] : '',
            'givenName'         => array_key_exists('givenName', $user) ? $user['givenName'] : '',
            'jobTitle'          => array_key_exists('jobTitle', $user) ? $user['jobTitle'] : '',
            'mail'              => array_key_exists('mail', $user) ? $user['mail'] : '',
            'mobilePhone'       => array_key_exists('mobilePhone', $user) ? $user['mobilePhone'] : '',
            'officeLocation'    => array_key_exists('officeLocation', $user) ? $user['officeLocation'] : '',
            'preferredLanguage' => array_key_exists('preferredLanguage', $user) ? $user['preferredLanguage'] : '',
            'surname'           => array_key_exists('surname', $user) ? $user['surname'] : '',
            'userPrincipalName' => array_key_exists('userPrincipalName', $user) ? $user['userPrincipalName'] : '',
        ]);
    }
}
