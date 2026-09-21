<?php

require __DIR__ . '/vendor/autoload.php';
use Firebase\JWT\JWT;
use Firebase\JWT\Key;

/**
 * OAuth2Service Reciever
 * This script lies on the end of the redirect_uri for the Mastodon application.
 * It recieves the grant code, exchanging it for a JWT to use with snappymail.
 * Optionally, it can also provision a new account if the user does not already have one.
 */

#Constants
$oauth_url = "https://transfur.social/oauth/authorize";
$reciever_base_url = "https://transfur.social/email/oauth2-reciever";
$token_url = "https://transfur.social/oauth/token";
$mastodon_root = "https://transfur.social";
$login_url = "https://transfur.social/email/?PostAuthJwtLogin";
$email_domain = "transfur.social";
$data_path = "/var/lib/oauth2service/";
$jwt_pkey_filename = "privkey.pem";
$oauth_secrets_filename = "oauth_secrets.json";
$autoprovision = true;
$autoprovision_url = "https://example.com/oauth2service.php";
$permittedRoles = array("Moderator","Admin","Owner");

#Secrets
$oauth_secrets = json_decode(file_get_contents($data_path . $oauth_secrets_filename), true);
$client_id = $oauth_secrets['client_id'];
$client_secret = $oauth_secrets['client_secret'];

#Variables
$authorize_url = $oauth_url . "?client_id=" . $client_id . "&redirect_uri=" . $reciever_base_url . "&response_type=code&scope=read:accounts";
$privateKey = file_get_contents($data_path . $jwt_pkey_filename);

#Input
$code = $_GET['code'] ?? null;
$error = $_GET['error'] ?? null;
$error_description = $_GET['error_description'] ?? null;

echo file_get_contents(__DIR__ . "/interstitial.html");

function exit_error($reason, $desc, $code, $destination = null, $destFriendly = "Login") {
    if($destination === null) {
        global $authorize_url;
        $destination = $authorize_url;
    }
    $buffer = ob_get_clean();
    $buffer = str_replace('$destination',$destination,$buffer);
    $buffer = str_replace('$destFriendly',$destFriendly,$buffer);
    echo $buffer;
    echo "<h2 id=error>Error: " . $reason . "</h2>";
    echo $desc . "<br/>";
    http_response_code($code);
    ob_end_flush();
    exit();
}

if ($error != null) {
    exit_error(
        $error,
        "Error Description: " . $error_description . "<br/>" .
        "Please make sure to AUTHORIZE the app to access your account.<br/>",
        400
    );
}

if ($code == null) {
    exit_error(
        "Invalid Response",
        "Please make sure to AUTHORIZE the app to access your account.<br/>",
        400
    );
}

$curl = curl_init();
curl_setopt($curl, CURLOPT_URL, $token_url);
curl_setopt($curl, CURLOPT_POST, 1);
curl_setopt($curl, CURLOPT_POSTFIELDS, "grant_type=authorization_code&client_id=" . $client_id . "&client_secret=" . $client_secret . "&code=" . $code . "&redirect_uri=" . $reciever_base_url);
curl_setopt($curl, CURLOPT_RETURNTRANSFER, true);
curl_setopt($curl, CURLOPT_HTTPHEADER, array('Content-Type: application/x-www-form-urlencoded'));
$token_response = curl_exec($curl);
curl_close($curl);

$token_response = json_decode($token_response, true);

//check if token response is valid
if ($token_response['error'] ?? null !== null) {
    exit_error(
        $token_response['error'],
		$token_response['error_description'] . "<br/>" .
        "Please make sure to AUTHORIZE the app to access your account.<br/>",
        400
    );
}

$curl = curl_init();
curl_setopt($curl, CURLOPT_URL, $mastodon_root . "/api/v1/accounts/verify_credentials");
curl_setopt($curl, CURLOPT_RETURNTRANSFER, true);
curl_setopt($curl, CURLOPT_HTTPHEADER, array('Authorization: Bearer ' . $token_response['access_token']));
$verify_response = curl_exec($curl);
curl_close($curl);

$verify_response = json_decode($verify_response, true);

//check if verify response is valid
if ($verify_response['error'] ?? null !== null) {
    exit_error(
        $verify_response['error'],
        "Please make sure to AUTHORIZE the app to access your account.<br/>",
        400
    );
}

// check if user has the email role
$roles = $verify_response['roles'];
$has_email_role = false;
foreach ($roles as $role) {
    $rolename = $role['name'];
    if(in_array($rolename, $permittedRoles)) {
        $has_email_role = true;
    }
}
if (!$has_email_role) {
    exit_error(
        "Your account is not authorized to use the Email service.",
        "You must be a Patron or be Verified to gain access.<br/>",
        403,
		$mastodon_root,
		"Mastodon"
    );
}

//check if user has credentials or not
if (!file_exists($data_path . $verify_response['id']) && $autoprovision == false) {
    exit_error(
        "Your account does not have an email address associated with it.",
        "You seem to be authorized for email access.<br/>" .
        "Please contact the webmaster for support.<br/>",
        500,
		$mastodon_root,
		"Mastodon"
    );
} else if (!file_exists($data_path . $verify_response['id']) && $autoprovision == true) {
    // generate random password
    $password = bin2hex(random_bytes(64));

    $salt = bin2hex(random_bytes(3));
    $passhash = $salt . hash("SHA256", $salt . $password);

    $provJwtPayload = [
        "iat" => time(),
        "exp" => time() + 60,
        "email" => $verify_response['username'] . "@" . $email_domain,
        "password" => $passhash
    ];

    $provJwt = JWT::encode($provJwtPayload, $privateKey, 'RS256');

    $curl = curl_init();
    curl_setopt($curl, CURLOPT_URL, $autoprovision_url);
    curl_setopt($curl, CURLOPT_POST, 1);
    curl_setopt($curl, CURLOPT_POSTFIELDS, "jwt=" . $provJwt);
    curl_setopt($curl, CURLOPT_RETURNTRANSFER, true);
    curl_setopt($curl, CURLOPT_HTTPHEADER, array('Content-Type: application/x-www-form-urlencoded'));
    $autoprovision_response = curl_exec($curl);
    curl_close($curl);
    $autoprovision_response = json_decode($autoprovision_response, true);
    if ($autoprovision_response['error'] !== null) {
        exit_error(
            $autoprovision_response['error'],
            "Please contact the webmaster for support.<br/>",
            500,
            $mastodon_root,
            "Mastodon"
        );
    }
    $file = fopen($data_path . $verify_response['id'], "w");
    fwrite($file, $password);
    fclose($file);
}

$jwtPayload = [
    'iat' => time(),
    'nbf' => time(),
    'exp' => time() + 3600,
    'sub' => $verify_response['id'],
    'email' => $verify_response['username'] . "@" . $email_domain,
];

$jwt = JWT::encode($jwtPayload, $privateKey, 'RS256');

echo
'<body onload="document.redirectform.submit()">   
    <form method="POST" action="' . $login_url . '" name="redirectform" style="display:none">
        <input name="jwt" value=' . $jwt . '>
    </form>
</body>';
