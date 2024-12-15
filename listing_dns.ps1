<#
	.SYNOPSIS
  		listing_dns.ps1
	.DESCRIPTION
		Script qui :
            -teste les noms de domaines avec différents TLDs afin de vérifier leur état HTTP
            -verifie si les FQDN sont achetables
            -cherche la présence de dispositifs de sécurité parmi : CSP, HSTS, SPF, Certificat SSL, XSS-Protection
            -cherche le regstrar et les DNS Record type SOA et MX
            -génère un fichier Excel avec les résultats
  	.PARAMETER Fichier
        Paramètre valide obligatoire
        Indique le chemin du fichier listant les noms de domaine à tester
		Le fichier passé en paramètre doit avoir cette forme :
            domain_name_a_tester1
            domain_name_a_tester2
            domain_name_a_tester3
            etc.
        Les noms de domaine ne doivent pas avoir de TLD
	.EXAMPLE
		.\listing_dns.ps1 -Fichier .\domain_names.txt
	.NOTES
	    Auteur : abbyle1
        /!\ Renseigner le chemin absolu de fichier Excel de sortie (variable $CheminFichierExcel)
        /!\ Fermer le fichier Excel avant enregistrement
    .API UTILISEES
        https://networkcalc.com/api/docs/
        https://developer.godaddy.com/
    .A AJOUTER
        Automatisation de la recherche de l'hébergeur
    .A AMELIORER
        Optimiser le code : infos stockées dans un tableau d'objets avec 1 attribut = 1 info, puis parcours entier du tableau pour les ajouter dans les cellules
        La verification de certificat n'aboutit pas dans des cas où elle le devrait
#>

param(
    [String] $Fichier
)

#   ------------------------------------------------------------------------------
#   ---                   Déclarations de variables                            ---
#   ------------------------------------------------------------------------------

$CheminFichierExcel = ""

$Tlds = @("app", "bzh", "co", "com", "fr", "io", "live", "net", "org", "nl")
# les TLDs suivants ne sont pas supportés par l'API godaddy :
$UnsupportedTlds = @("bzh", "fr")
# Tableau contenant des objets composés de plusieurs attributs
$Global:Datas = @()

#   ------------------------------------------------------------------------------
#   ---                   Fonctions spécifiques au script                      ---
#   ------------------------------------------------------------------------------

Function Get-EtatHTTPS {
    param([String] $Url)
    try {
        $Response = Invoke-WebRequest -Uri $Url -TimeoutSec 30
        Write-Host "Suc for $Url`t` $($Response.StatusCode)"
        $Code = $($Response.StatusCode) -replace '[^\d]+', ''
        $CSP = $false
        $HSTS = $false
        $XSS_Prot = $false
        foreach ($Header in $Response.Headers.GetEnumerator()) {
            if ($Header.Key.ToLower().Contains("content-security-policy")) {
                $CSP = $Header.Value
            }
            if ($Header.Key.ToLower().Contains("strict-transport-security")) {
                $HSTS = $Header.Value
            }
            if ($Header.Key.ToLower().Contains("x-xss-protection")) {
                $XSS_Prot = $Header.Value
            }
            if ($CSP -ne $false -and $HSTS -ne $false -and $XSS_Prot -ne $false) {
                break
            }
        }
        return $Code, $CSP, $HSTS, $XSS_Prot
    } catch {
        $ErrorMessage = $_.Exception.Message
        Write-Host "Err for $Url`t` $ErrorMessage"
        # On recupere les caractères correspondant à des chiffres
        $Code = $ErrorMessage -replace '[^\d]+', ''
        # Il n'y pas toujours de code retour :
        if ($Code -eq '') {
            return "ko : $ErrorMessage", "-", "-", "-"
        } else {
            return $Code, "-", "-", "-"
        }
    }
}

Function Get-AvailOrTaken {
    param([String] $DomainName)
    $Tld = $DomainName.Split(".")[-1]
    if ($Tld -in $UnsupportedTlds) {
        return "unsupported tld by api"
    } elseif ($DomainName.Split('.').Count -gt 2) {
        return "sous-domaine"
    } else {
        $API_KEY = ""
        $API_SECRET = ""
        $Headers = @{
            "Authorization" = "sso-key ${API_KEY}:${API_SECRET}"
            "Accept" = "application/json"
        }
        $Url = "https://api.ote-godaddy.com/v1/domains/available?domain=$DomainName"
        try {
            $Response = Invoke-WebRequest -Uri $Url -Headers $Headers
            $JsonObject = $Response | ConvertFrom-Json
            return $JsonObject.available
        } catch {
            Write-Host "Err for $Url`t` $($_.Exception.Message)"
            return $_.Exception.Message
        }
    }   
}

Function Get-Certificate {
    param([String] $Url)
    # Create a WebRequest to the URI
    $webRequest = [System.Net.HttpWebRequest]::Create($Url)
    $webRequest.AllowAutoRedirect = $false
    $webRequest.Timeout = 10000
    try {
        # Get the response from the request
        $response = $webRequest.GetResponse()
        $response.Close()
    } catch [System.Net.WebException] {
        $response = $_.Exception.Response
        if ($response -ne $null) {
            $response.Close()
        }
    }
    # Retrieve the SSL certificate
    $certificate = $webRequest.ServicePoint.Certificate
    if ($certificate -ne $null) {
        # Output the certificate details
        $cert2 = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2 $certificate
        Write-Host "Subject: $($cert2.Subject)"
        Write-Host "Issuer: $($cert2.Issuer)"
        Write-Host "Thumbprint: $($cert2.Thumbprint)"
        Write-Host "Effective Date: $($cert2.NotBefore)"
        Write-Host "Expiration Date: $($cert2.NotAfter)"
        # Check the certificate chain
        $chain = New-Object System.Security.Cryptography.X509Certificates.X509Chain
        $chain.Build($cert2) | Out-Null
        foreach ($status in $chain.ChainStatus) {
            Write-Host "Chain Status: $($status.Status) - $($status.StatusInformation)"
        }
        if ($chain.ChainStatus[0].StatusInformation -ne $null) {
            return $chain.ChainStatus[0].StatusInformation, $chain.ChainStatus[1].StatusInformation
        }
        return $true, $($cert2.NotAfter)
    } else {
        Write-Error "No SSL certificate found for $Url."
        return $($_.Exception.Message), ""
    }
}

Function Get-MxSoa {
    param([String] $DomainName)
    try {
        $resp = Invoke-WebRequest -Uri "https://networkcalc.com/api/dns/lookup/$DomainName" -Method GET | ConvertFrom-Json
        $exchange = $resp.records.MX.exchange
        $priority = $resp.records.MX.priority
        $nameserver = $resp.records.SOA.nameserver
        $hostmaster = $resp.records.SOA.hostmaster
        return "$exchange ; $priority", "$nameserver ; $hostmaster"
    } catch {
        return "-", "-"
    }
}

Function Get-Registrar {
    param([String] $DomainName)
    try {
        $resp = Invoke-WebRequest -Uri "https://networkcalc.com/api/dns/whois/$DomainName" -Method GET | ConvertFrom-Json
        return $resp.whois.registrar
    } catch {
        return $_.Exception.Message
    }
}

Function Get-SPF {
    param([String] $DomainName)
    try {
        $resp = Invoke-WebRequest -Uri "https://networkcalc.com/api/dns/spf/$DomainName" -Method POST | ConvertFrom-Json
        return $resp.spf
    } catch {
        if ($_.Exception.Message.Contains("400")) {
            return "-"
        }
        return $_.Exception.Message
    }
}

Function Create-Excel {
    # Créez un nouvel objet Excel
    $Excel = New-Object -ComObject Excel.Application
    # Créez un nouveau Classeur Excel
    $Classeur = $Excel.Workbooks.Add()
    # Sélectionnez la première Feuille de calcul
    $Feuille = $Classeur.Worksheets.Item(1)
    $Feuille.Cells.Item(1, 1) = "URL"
    $Feuille.Cells.Item(1, 2) = "Code Retour"
    $Feuille.Cells.Item(1, 3) = "Available"
    $Feuille.Cells.Item(1, 4) = "Certificat"
    $Feuille.Cells.Item(1, 5) = "Date Expiration"
    $Feuille.Cells.Item(1, 6) = "CSP"
    $Feuille.Cells.Item(1, 7) = "HSTS"
    $Feuille.Cells.Item(1, 8) = "XSS Protection"
    $Feuille.Cells.Item(1, 9) = "MX (exchange ; priority)"
    $Feuille.Cells.Item(1, 10) = "SOA (nameserver ; hostmaster)"
    $Feuille.Cells.Item(1, 11) = "Registrar"
    $Feuille.Cells.Item(1, 12) = "SPF"
    for ($i = 0; $i -lt $Datas.Count; $i++) {
        $Feuille.Cells.Item($i + 2, 1) = $Datas[$i].URL
        $Feuille.Cells.Item($i + 2, 2) = $Datas[$i].Code_Retour
        $Feuille.Cells.Item($i + 2, 3) = $Datas[$i].Available
        $Feuille.Cells.Item($i + 2, 4) = $Datas[$i].Certificat
        $Feuille.Cells.Item($i + 2, 5) = $Datas[$i].Date_Expiration
        $Feuille.Cells.Item($i + 2, 6) = $Datas[$i].CSP
        $Feuille.Cells.Item($i + 2, 7) = $Datas[$i].HSTS
        $Feuille.Cells.Item($i + 2, 8) = $Datas[$i].XSS_Protection
        $Feuille.Cells.Item($i + 2, 9) = $Datas[$i].MX
        $Feuille.Cells.Item($i + 2, 10) = $Datas[$i].SOA
        $Feuille.Cells.Item($i + 2, 11) = $Datas[$i].Registrar
        $Feuille.Cells.Item($i + 2, 12) = $Datas[$i].SPF
        # Desactiver l'auto-formatage du texte
        $Feuille.Cells.Item($i + 2, 4).WrapText = $false
        $Feuille.Cells.Item($i + 2, 5).WrapText = $false
    }
    # Ajustement de colonnes :
    $Feuille.Columns.Item(1).AutoFit()
    $Classeur.SaveAs($CheminFichierExcel)
    $Excel.Quit()
    # Nettoyez les objets COM de la mémoire
    [System.Runtime.Interopservices.Marshal]::ReleaseComObject($Feuille)
    [System.Runtime.Interopservices.Marshal]::ReleaseComObject($Classeur)
    [System.Runtime.Interopservices.Marshal]::ReleaseComObject($Excel)
    [System.GC]::Collect()
    [System.GC]::WaitForPendingFinalizers()
    Write-Host "Le fichier Excel a été créé et enregistré à l'emplacement : $CheminFichierExcel"
}

#   ------------------------------------------------------------------------------
#   ---                   Prérequis                                            ---
#   ------------------------------------------------------------------------------

if (-not $Fichier) {
    Write-Host "Erreur : Aucun chemin de fichier spécifié. Veuillez fournir un chemin valide."
    Write-Host "Exemple : .\listing_dns.ps1 -Fichier .\domain_names.txt"
    exit 1
}

if (-not (Test-Path -Path $Fichier)) {
    Write-Host "Erreur : Le fichier '$Fichier' n'existe pas."
    exit 1
}

Write-Warning "Renseigner le chemin du fichier Excel dans le code"
Write-Warning "Fermer le fichier Excel avant enregistrement"
$Saisie = Read-Host "Continuer? [y/n]"
$Saisie = $Saisie.ToLower()

while ($Saisie -ne 'y' -and $Saisie -ne 'n') {
    $Saisie = Read-Host "Erreur saisie invalide. Continuer? [y/n]"
    $Saisie = $Saisie.ToLower()
}

if ($Saisie -eq 'n') {
    exit 1
}

#---------------------------------------------------------------------------------------------------------------------
#---                                                   PROGRAMME PRINCIPAL                                         ---
#---------------------------------------------------------------------------------------------------------------------

Function Process-Domain {
    param (
        [string]$Url,
        [string]$Sld,
        [string]$Tld = $null
    )

    # Création de l'objet :
    $Ligne = [PSCustomObject]@{
        URL = $Url
        Code_Retour = ""
        Available = ""
        Certificat = ""
        Date_Expiration = ""
        CSP = ""
        HSTS = ""
        XSS_Protection = ""
        MX = ""
        SOA = ""
        Registrar = ""
        SPF = ""
    }

    # Obtention des infos :
    $Ligne.Code_Retour,
    $Ligne.CSP,
    $Ligne.HSTS,
    $Ligne.XSS_Protection = Get-EtatHTTPS -Url $Url

    $DomainName = "$Sld.$Tld"
    if ($Tld -eq $null) {
        # on agit sur "twitter.com" si on a "twitter.com/nom_page"
        $DomainName = $Url.Split('/')[2]
    }
    $Ligne.Available = Get-AvailOrTaken -DomainName $DomainName
    $Ligne.MX, 
    $Ligne.SOA = Get-MxSoa -DomainName $DomainName
    $Ligne.Registrar = Get-Registrar -DomainName $DomainName
    $Ligne.SPF = Get-SPF -DomainName $DomainName

    if ($Ligne.Code_Retour -eq '200' -or $Ligne.Code_Retour -eq '403') {
        $Ligne.Certificat,
        $Ligne.Date_Expiration = Get-Certificate -Url $Url
    }

    $Global:Datas += $Ligne
}

$FileContent = Get-Content $Fichier

foreach ($Sld in $FileContent) {
    # Si l'URL concerne une page web (ex : twitter.com/nom_page)
    if ($Sld.Contains("/")) {
        $Url = "https://$Sld"
        Process-Domain -Url $Url -Sld $Sld
    } else {
        foreach ($Tld in $Tlds) {
            $Url = "https://$Sld.$Tld"
            Process-Domain -Url $Url -Sld $Sld -Tld $Tld
        }
    }
    Write-Host `r`
}

Write-Output "Recap :"
Write-Output $Global:Datas

Create-Excel

