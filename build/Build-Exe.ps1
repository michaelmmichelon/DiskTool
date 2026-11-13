# Gera ..\DiskTool.exe a partir de ..\DiskTool.ps1 (rode de novo sempre que alterar o script).
#
# Assinatura digital (opcional - reduz o aviso do SmartScreen):
#   .\Build-Exe.ps1 -CertThumbprint <impressão digital de um certificado de assinatura de código já instalado>
#   .\Build-Exe.ps1 -PfxPath C:\certs\meu_certificado.pfx      (pede a senha do .pfx)
param([string]$CertThumbprint, [string]$PfxPath, [string]$TimestampServer = 'http://timestamp.digicert.com')

$ErrorActionPreference = 'Stop'
$here = Split-Path -Parent $PSCommandPath
$root = Split-Path -Parent $here
$csc  = Join-Path $env:WINDIR 'Microsoft.NET\Framework64\v4.0.30319\csc.exe'
$ico  = Join-Path $here 'DiskTool.ico'
$out  = Join-Path $root 'DiskTool.exe'

# --- Ícone (gerado uma vez): disco com indicador verde de saúde
if (-not (Test-Path $ico)) {
    Add-Type -AssemblyName System.Drawing
    $pngs = foreach ($s in 16, 32, 48, 256) {
        $bmp = New-Object Drawing.Bitmap $s, $s
        $g = [Drawing.Graphics]::FromImage($bmp)
        $g.SmoothingMode = 'AntiAlias'
        $k = $s / 256.0
        $path = New-Object Drawing.Drawing2D.GraphicsPath
        $r = 40 * $k; $x = 16 * $k; $y = 16 * $k; $w = 224 * $k
        $path.AddArc($x, $y, $r, $r, 180, 90); $path.AddArc($x + $w - $r, $y, $r, $r, 270, 90)
        $path.AddArc($x + $w - $r, $y + $w - $r, $r, $r, 0, 90); $path.AddArc($x, $y + $w - $r, $r, $r, 90, 90)
        $path.CloseFigure()
        $g.FillPath((New-Object Drawing.SolidBrush ([Drawing.Color]::FromArgb(45, 55, 72))), $path)
        $g.FillEllipse((New-Object Drawing.SolidBrush ([Drawing.Color]::FromArgb(200, 208, 220))), 44 * $k, 44 * $k, 168 * $k, 168 * $k)
        $g.FillEllipse((New-Object Drawing.SolidBrush ([Drawing.Color]::FromArgb(45, 55, 72))), 110 * $k, 110 * $k, 36 * $k, 36 * $k)
        $g.FillEllipse((New-Object Drawing.SolidBrush ([Drawing.Color]::FromArgb(40, 190, 90))), 168 * $k, 168 * $k, 72 * $k, 72 * $k)
        $g.Dispose()
        $ms = New-Object IO.MemoryStream
        $bmp.Save($ms, [Drawing.Imaging.ImageFormat]::Png)
        ,@($s, $ms.ToArray())
    }
    $fs = [IO.File]::Create($ico); $bw = New-Object IO.BinaryWriter $fs
    $bw.Write([uint16]0); $bw.Write([uint16]1); $bw.Write([uint16]$pngs.Count)
    $offset = 6 + 16 * $pngs.Count
    foreach ($p in $pngs) {
        $dim = [byte]($p[0] % 256)
        $bw.Write($dim); $bw.Write($dim); $bw.Write([byte]0); $bw.Write([byte]0)
        $bw.Write([uint16]1); $bw.Write([uint16]32); $bw.Write([uint32]$p[1].Length); $bw.Write([uint32]$offset)
        $offset += $p[1].Length
    }
    foreach ($p in $pngs) { $bw.Write($p[1]) }
    $bw.Close()
}

& $csc /nologo /target:winexe /platform:x64 /optimize+ /codepage:65001 `
    "/out:$out" "/win32icon:$ico" "/win32manifest:$(Join-Path $here 'app.manifest')" `
    "/resource:$(Join-Path $root 'DiskTool.ps1'),DiskTool.ps1" `
    /reference:System.Windows.Forms.dll `
    (Join-Path $here 'Launcher.cs')
if ($LASTEXITCODE -ne 0) { throw 'Falha na compilação.' }
Write-Host "Gerado: $out"

# --- Assinatura digital (somente se um certificado for informado)
$cert = $null
if ($CertThumbprint) {
    $thumb = $CertThumbprint.Replace(' ', '').ToUpper()
    $cert = Get-ChildItem Cert:\CurrentUser\My, Cert:\LocalMachine\My -CodeSigningCert |
            Where-Object { $_.Thumbprint -eq $thumb } | Select-Object -First 1
    if (-not $cert) { throw "Certificado de assinatura de código $CertThumbprint não encontrado." }
} elseif ($PfxPath) {
    $cert = Get-PfxCertificate -FilePath $PfxPath
}
if ($cert) {
    $sig = Set-AuthenticodeSignature -FilePath $out -Certificate $cert -HashAlgorithm SHA256 -TimestampServer $TimestampServer
    Write-Host "Assinatura: $($sig.Status) - $($sig.StatusMessage)"
}
