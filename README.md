# snappymail-plugins

Home of the plugins and scripts powering the Transfur.social email system.

# Components
 - [oauth2-reciever](/oauth2-reciever.php): OAuth2 redirect_uri target, Verifies a user and provides a JWT for snappymail. Generates and stores passwords automatically if auto-provisioning is enabled.
 - [index.php](/index.php): The snappymail extension that permits JWT as a login source & fetches credentials from disk.
 - [oauth2service.php](/oauth2service.php): Auto-provisioning script, Invoked by oauth2-reciever to initialize an account on the hMailServer.
 - [SnappyMail](https://snappymail.eu): The open source webmail frontend in use for this project. A fork of the now-defunct RainLoop.
