# AgentTikus

_**Disclaimer: This project is only meant for educational purpose only and do not use this against other people. Any illegal use of this repo is strictly at your own responsibilty and risk.**_

## What it does?
* Create a ransom asymmetric keys (AES) and encrypt files and folder. 
* Encrypted files/folders are then uploaded to Dropbox client
* Generate RSA key pairs and encrypt AES keys with victim's public key
* Encrypt victim's private key and stored in Dropbox client
* All encrypted keys are then stored in Registry Keys under `\HKEY_LOCAL_MACHINE\SOFTWARE\FreePalestine`

![poc](./src/image.png)


## Video POC
![video](https://player.vimeo.com/video/576425602?badge=0&amp;autopause=0&amp;player_id=0&amp;app_id=58479)