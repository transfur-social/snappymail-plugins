<?php
require __DIR__ . '/vendor/autoload.php';
use Firebase\JWT\JWT;
use Firebase\JWT\Key;

/**
 * OAuth2Service provisioning tool.
 * Oxymoronically has nothing to do with OAuth2 at all.
 * This script fields a request from oauth2-reciever.php, verifies its JWT, and then creates a new email account.
 */

$jwt_public_key = "";

$boundary = sha1(uniqid());
$onboardingSubject = "Welcome to your new mailbox.";
//TODO This is very hacky and fragile. Updating this to use a library is preferable. 
$onboardingMessage = "--$boundary
Content-Type: text/html;charset=UTF-8
Content-Transfer-Encoding: quoted-printable
Content-ID: text-body

<html><body><h1>Welcome to your new mailbox</h1>Your inbox is ready t=
o use.<br><br>Please use it responsibly and don't spam.<br><br>Thank =
you for chosing our mail service.</body></html>

--$boundary
Content-Type: text/plain;charset=UTF-8
Content-Transfer-Encoding: quoted-printable
Content-ID: text-body

Welcome to your new mailbox

Please use it responsibly and don't spam.

Thank you for choosing our mail service.

--$boundary--";
$fromtag = "Email Service Administrator <no-reply@example.com>";
$replyto = "postmaster@example.com";

$email_domain = "example.com";
$host = "localhost:3306";
$dbname = "mail";
$user = "mail";
$pass = "changeMe123";

$jwt = $_POST['jwt'];

$payload = null;

try {
    $payload = JWT::decode($jwt, new Key($jwt_public_key, "RS256"));
} catch (Throwable $e) {
    echo '{"error":"invalid_s2s_jwt","message":"'.$e->getMessage().'"}';
    http_response_code(400);
    exit();
}

$sEmail = $payload->email;
$sPasshash = $payload->password;

$dsn = 'mysql:host=' . $host . ';dbname=' . $dbname . ';charset=utf8';
$options = array(
    PDO::ATTR_EMULATE_PREPARES  => true,
    PDO::ATTR_PERSISTENT        => true,
    PDO::ATTR_ERRMODE           => PDO::ERRMODE_EXCEPTION
);

try {
    $conn = new PDO($dsn, $user, $pass, $options);

    $existingAccounts = $conn->query("SELECT accountpassword FROM hm_accounts WHERE accountaddress = '".$sEmail."'")->fetch();
    //error if any are found
    if ($existingAccounts && count($existingAccounts) > 0) {
        echo '{"error":"account_exists"}';
        http_response_code(400);
        exit();
    }

    //sanity check the email
    if (!filter_var($sEmail, FILTER_VALIDATE_EMAIL)) {
        echo '{"error":"invalid_email"}';
        http_response_code(400);
        exit();
    }

    //sanity check the email is for our domain
    if (strpos($sEmail, '@') === false || substr($sEmail, strpos($sEmail, '@') + 1) !== $email_domain) {
        echo '{"error":"invalid_email"}';
        http_response_code(400);
        exit();
    }

    //sanity check the password
    if (strlen($sPasshash) != 70) {
        echo '{"error":"invalid_passhash"}';
        http_response_code(400);
        exit();
    }

    $domain = $conn->query("SELECT domainid FROM hm_domains WHERE domainname = '".$email_domain."'")->fetch()[0];

    //find next account id

    $inserted = $conn->prepare("INSERT INTO `".$dbname."`.`hm_accounts` (`accountdomainid`, `accountadminlevel`, `accountaddress`, `accountpassword`, `accountactive`, `accountisad`, `accountaddomain`, `accountadusername`, `accountmaxsize`, `accountvacationmessageon`, `accountvacationmessage`, `accountvacationsubject`, `accountpwencryption`, `accountforwardenabled`, `accountforwardaddress`, `accountforwardkeeporiginal`, `accountenablesignature`, `accountsignatureplaintext`, `accountsignaturehtml`, `accountlastlogontime`, `accountvacationexpires`, `accountvacationexpiredate`, `accountpersonfirstname`, `accountpersonlastname`) VALUES (?, 0, ?, ?, 1, 0, '', '', 0, 0, '', '', 3, 0, '', 1, 0, '', '', '1970-01-01 00:00:00', 0, '1970-01-01 00:00:00', '', '');")
        ->execute([$domain, $sEmail, $sPasshash]);
    
    if ($inserted) {
        $newAccount = $conn->query("SELECT accountid FROM hm_accounts WHERE accountaddress = '".$sEmail."'")->fetch()[0];
        $conn->prepare("INSERT INTO `".$dbname."`.`hm_imapfolders` (folderaccountid, folderparentid, foldername,folderissubscribed,foldercreationtime,foldercurrentuid) VALUES (?,-1,'INBOX',1,'1970-01-01 00:00:00',0);")->execute([$newAccount]);
        mail(
            $sEmail,
            $onboardingSubject,
            $onboardingMessage,
            ["From" => $fromtag,"MIME-Version"=>"1.0", "Content-Type" => 'multipart/alternative; boundary="'.$boundary.'"', "Reply-To" => $replyto]
        );
        echo '{"success":"true"}';
        http_response_code(201);
        exit();
    } else {
        echo $conn->errorInfo();
        echo '{"error":"internal_error"}';
        http_response_code(500);
        exit();
    }
    
} catch (Exception $e) {
    echo $e->getMessage();
    echo '{"error":"internal_error"}';
    http_response_code(500);
    exit();
}

?>
