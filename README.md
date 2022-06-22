# esup-otp-cas-server

CAS server which delegates to another server the password check + asks for OTP

It asks for long-term validation of OTP.

It can optionnaly bypass OTP if the user has not activated any methods.

### Requirements
- [esup-otp-api](https://github.com/EsupPortail/esup-otp-api)

### Installation
- git clone https://github.com/EsupPortail/esup-otp-cas-server
- npm install
- change the fields values in conf.js to your installation
- npm start


License
----

MIT
   [EsupPortail]: <https://www.esup-portail.org/>
