Yet another binding for http://www.deathbycaptcha.com/

Uses HTTP API in order to prepare and send request to bypass captcha.

See http://www.deathbycaptcha.com/user/api for more details.

Example usage:

recognize $ pngCaptcha "username" "password" (mkFilePath "index.png")
