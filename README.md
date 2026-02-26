# Projet UDP

## Description

Ce projet permet à un **ClientA** et un **ClientB** d’échanger des fichiers de manière sécurisée via un **serveur** en utilisant :  

- **DTLS** (Datagram TLS) sur UDP pour sécuriser le transport  
- **AES-256-CBC** pour chiffrer le contenu des fichiers  
- **RSA** pour chiffrer la clé AES pour le destinataire  
- **Token** pour l’authentification des clients  

Le serveur gère les commandes **UPLOAD** et **DOWNLOAD** et permet de stocker temporairement les fichiers chiffrés avant de les transmettre au destinataire.
