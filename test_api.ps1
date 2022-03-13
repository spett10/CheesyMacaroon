$baseUrl = "https://localhost:49155"
function FromBase64([string]$str) {
    [text.encoding]::utf8.getstring([convert]::FromBase64String($str))
}

function ToBase64([string]$str) {
    [convert]::ToBase64String([text.encoding]::utf8.getBytes($str))
}

function ToBase64Url([string]$str) {
    (ToBase64($str)) -replace "=", '' -replace "\+", "-" -replace "/", "_"
}

function FromBase64Url([string]$str) {
    $str = $str -replace "-", "\+" -replace "_", "/"

    switch ($str.Length % 4) {
        0 { break }
        2 { $str += '=='; break }
        3 { $str += '='; break }
        Default { Write-Warning 'Illegal base64 url string'}
    }

    FromBase64($str)
}

$weatherforecastUrl = $baseUrl + "/weatherforecast"
$macaroonUrl = $baseUrl + "/macaroon"
$attenuateUrl = $macaroonUrl + "/attenuate/Soren"
$authenticateUrl = $macaroonUrl + "/authenticate/"

Write-Host "Calling $weatherforecastUrl without valid macaroon"
$unauthweatherforecast = Invoke-WebRequest -Uri $weatherforecastUrl -Headers @{ Authorization = "Bearer " }
Write-Host "Https Status Code: " $unauthweatherforecast.StatusCode
Write-Host ""

Write-Host "Calling $macaroonUrl to get macaroon"
$macaroon = (Invoke-WebRequest -Uri $macaroonUrl).Content
Write-Host "Got macaroon: $macaroon"
Write-Host ""
Write-Host (FromBase64Url $macaroon)
Write-Host ""

Write-Host "Calling $weatherforecastUrl with fresh macaroon"
$authHeader = @{ Authorization = "Bearer " + $macaroon }
$weatherforecast = Invoke-WebRequest -Uri $weatherforecastUrl -Headers $authHeader
Write-Host "Http Status Code:" $weatherforecast.StatusCode
Write-Host ""

Write-Host "Attenuating macaroon at $attenuateUrl"
$attenuatedMacaroon = (Invoke-WebRequest -Uri $attenuateUrl -Headers $authHeader).Content
Write-Host "Got attenuated macaroon:" $attenuatedMacaroon
Write-Host ""
Write-Host (FromBase64Url $attenuatedMacaroon)
Write-Host ""

Write-Host "Calling $weatherforecastUrl with attenuated macaroon, but no discharge macaroon!"
$authHeader = @{ Authorization = "Bearer " + $attenuatedMacaroon }
$weatherforecast = Invoke-WebRequest -Uri $weatherforecastUrl -Headers $authHeader

Write-Host "Trying to authenticate at $authenticateUrl to obtain discharge"
$basicAuth = ToBase64 'Soren:password1234'
$basicAuthHeader = @{ Authorization = "Basic " + $basicAuth }
$discharge = (Invoke-WebRequest -Uri ($authenticateUrl + $attenuatedMacaroon) -Headers $basicAuthHeader).Content
Write-Host "Got Discharge Macaroon: " $discharge
Write-Host ""
Write-Host (FromBase64Url $discharge)
Write-Host ""