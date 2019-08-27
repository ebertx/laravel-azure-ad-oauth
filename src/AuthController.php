<?php

namespace Metrogistics\AzureSocialite;

use Illuminate\Routing\Controller;
use Laravel\Socialite\Facades\Socialite;

class AuthController extends Controller
{
    public function redirectToOauthProvider()
    {
        return Socialite::driver('azure-oauth')->redirect();
    }

    public function handleOauthResponse()
    {
        $user = Socialite::driver('azure-oauth')->user();

        return dd($user);
        if($user->email == null){ // the email is null (Not associated with account)
            if($user->user['mail'] == null){ // the saml email is also not configured
                $user->email = $user->user['userPrincipalName'];
                $user->user['mail'] = $user->user['userPrincipalName'];
            } else {
                $user->email = $user->user['mail'];
            }
        }

        $authUser = $this->findOrCreateUser($user);

        auth()->login($authUser, true);

        // session([
        //     'azure_user' => $user
        // ]);

        return redirect(
            config('azure-oath.redirect_on_login')
        );
    }

    protected function findOrCreateUser($user)
    {
        $user_class = config('azure-oath.user_class');
        $authUser = $user_class::where(config('azure-oath.user_id_field'), $user->id)->first();

        if ($authUser) {
            return $authUser;
        }

        $UserFactory = new UserFactory();

        return $UserFactory->convertAzureUser($user);
    }
}
