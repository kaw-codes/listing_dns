## DESCRIPTION DU SCRIPT
- teste des noms de domaines avec différents TLDs afin de vérifier leur état HTTP
- verifie s'ils sont achetables
- cherche la présence de dispositifs de sécurité parmi : CSP, HSTS, SPF, Certificat SSL, XSS-Protection
- cherche le registrar et les DNS Record type SOA et MX
- génère un fichier Excel avec les résultats

## PARAMETER 'Fichier'
Paramètre valide obligatoire\
Indique le chemin du fichier listant les noms de domaine à tester\
Le fichier passé en paramètre doit avoir cette forme :
>domain_name_a_tester1\
domain_name_a_tester2\
domain_name_a_tester3\
etc.

Les noms de domaine ne doivent pas avoir de TLD

## EXEMPLE
.\listing_dns.ps1 -Fichier .\domain_names.txt

## API UTILISEES
https://networkcalc.com/api/docs/ \
https://developer.godaddy.com/

## A AJOUTER
- Automatisation de la recherche de l'hébergeur.

## A AMELIORER
- Optimiser le code : infos stockées dans un tableau d'objets avec 1 attribut = 1 info, puis parcours entier du tableau pour les ajouter dans les cellules.
- La verification de certificat n'aboutit pas dans des cas où elle le devrait.
