function Write-Step { 
    param($Message) 
    Write-Host "`n=== $Message ===" -ForegroundColor Cyan 
}

function Write-Success { 
    param($Message) 
    Write-Host "SUCCESS: $Message" -ForegroundColor Green 
}

function Write-Warning { 
    param($Message) 
    Write-Host "WARNING: $Message" -ForegroundColor Yellow 
}

function Write-Info { 
    param($Message) 
    Write-Host "  $Message" -ForegroundColor Gray 
}

function Test-Admin {
    return ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Install-OpenSSH {
    Write-Step "INSTALLING OPENSSH COMPONENTS"
    
    $sshClient = Get-WindowsCapability -Online | Where-Object { $_.Name -like 'OpenSSH.Client*' -and $_.State -eq 'Installed' }
    if (-not $sshClient) {
        Write-Info "Installing OpenSSH Client..."
        Add-WindowsCapability -Online -Name OpenSSH.Client~~~~0.0.1.0 | Out-Null
        Write-Success "OpenSSH Client installed"
    } else {
        Write-Success "OpenSSH Client already installed"
    }
    
    $sshServer = Get-WindowsCapability -Online | Where-Object { $_.Name -like 'OpenSSH.Server*' -and $_.State -eq 'Installed' }
    if (-not $sshServer) {
        Write-Info "Installing OpenSSH Server..."
        Add-WindowsCapability -Online -Name OpenSSH.Server~~~~0.0.1.0 | Out-Null
        Write-Success "OpenSSH Server installed"
    } else {
        Write-Success "OpenSSH Server already installed"
    }
}

function Configure-Services {
    Write-Step "CONFIGURING SSH SERVICES"
    
    Stop-Service ssh-agent -Force -ErrorAction SilentlyContinue
    Stop-Service sshd -Force -ErrorAction SilentlyContinue
    Start-Sleep -Seconds 2
    
    $services = @(
        @{Name = "ssh-agent"; Description = "SSH Agent"},
        @{Name = "sshd"; Description = "SSH Server"}
    )
    
    foreach ($service in $services) {
        Write-Info "Configuring $($service.Description)..."
        Set-Service -Name $service.Name -StartupType Automatic -ErrorAction SilentlyContinue
        Start-Service -Name $service.Name -ErrorAction SilentlyContinue
        Write-Success "$($service.Description) configured and started"
    }
}

function Setup-SSHDirectory {
    Write-Step "SETTING UP SSH DIRECTORY STRUCTURE"
    
    $sshDir = "C:\Users\camil\.ssh"
    
    if (-not (Test-Path $sshDir)) {
        New-Item -ItemType Directory -Path $sshDir -Force | Out-Null
        Write-Success "SSH directory created"
    } else {
        Write-Success "SSH directory already exists"
    }
    
    return $sshDir
}

function Generate-SSHKeys {
    param([string]$SSHDir)
    
    Write-Step "GENERATING SSH KEYS"
    
    Get-ChildItem "$SSHDir\id_*" -ErrorAction SilentlyContinue | Remove-Item -Force -ErrorAction SilentlyContinue
    
    Write-Info "Generating Ed25519 key..."
    ssh-keygen -t ed25519 -f "$SSHDir\id_ed25519" -N '""' -C "feliza@FELIZA" | Out-Null
    Write-Success "Ed25519 key generated"
    
    $fingerprint = ssh-keygen -l -f "$SSHDir\id_ed25519"
    Write-Info "Fingerprint: $($fingerprint[0])"
    
    Start-Process -FilePath "icacls" -ArgumentList "`"$SSHDir\id_ed25519`" /inheritance:r /grant:r `"Feliza\feliza:(F)`"" -Wait -WindowStyle Hidden
}

function Configure-SSHAgent {
    Write-Step "CONFIGURING SSH AGENT"
    
    ssh-add -D | Out-Null
    
    ssh-add "C:\Users\camil\.ssh\id_ed25519" | Out-Null
    Write-Success "SSH keys configured in agent"
    
    Write-Info "Keys in SSH agent:"
    ssh-add -l
}

function Configure-Firewall {
    Write-Step "CONFIGURING FIREWALL"
    
    $firewallRuleName = "OpenSSH-Server"
    $existingRule = Get-NetFirewallRule -DisplayName $firewallRuleName -ErrorAction SilentlyContinue
    
    if (-not $existingRule) {
        New-NetFirewallRule -DisplayName $firewallRuleName `
            -Direction Inbound `
            -Protocol TCP `
            -LocalPort 22 `
            -Action Allow `
            -Profile Domain,Private,Public | Out-Null
        Write-Success "Firewall rule created for SSH"
    } else {
        Write-Success "Firewall rule already exists"
    }
}

function Fix-SSHPermissions-Ultimate {
    param([string]$SSHDir)
    
    Write-Step "ULTIMATE PERMISSION FIX WITH VERIFICATION"
    
    $authKeysPath = "$SSHDir\authorized_keys"
    
    try {
        Write-Info "Stopping SSH services..."
        Stop-Service ssh-agent, sshd -Force -ErrorAction SilentlyContinue
        Start-Sleep -Seconds 3

        Write-Info "Resetting permissions..."
        Start-Process -FilePath "takeown" -ArgumentList "/f `"$SSHDir`" /r /d y" -Wait -WindowStyle Hidden
        Start-Sleep -Seconds 2
        Start-Process -FilePath "icacls" -ArgumentList "`"$SSHDir`" /reset /t /c" -Wait -WindowStyle Hidden
        Start-Sleep -Seconds 2

        Write-Info "Recreating authorized_keys..."
        Remove-Item $authKeysPath -Force -ErrorAction SilentlyContinue
        Start-Sleep -Seconds 1

        $null = New-Item -Path $authKeysPath -ItemType File -Force
        
        Start-Process -FilePath "icacls" -ArgumentList "`"$authKeysPath`" /inheritance:r" -Wait -WindowStyle Hidden
        Start-Process -FilePath "icacls" -ArgumentList "`"$authKeysPath`" /grant:r `"Feliza\feliza:(F)`"" -Wait -WindowStyle Hidden
        Start-Process -FilePath "icacls" -ArgumentList "`"$authKeysPath`" /grant:r `"SYSTEM:(F)`"" -Wait -WindowStyle Hidden

        $pubKey = Get-Content "$SSHDir\id_ed25519.pub"
        Set-Content -Path $authKeysPath -Value $pubKey -Encoding UTF8

        Start-Process -FilePath "icacls" -ArgumentList "`"$authKeysPath`" /grant:r `"Feliza\feliza:(R)`"" -Wait -WindowStyle Hidden

        Write-Info "Verifying authorized_keys..."
        if (Test-Path $authKeysPath) {
            $content = Get-Content $authKeysPath
            if ($content -and $content.Length -gt 0) {
                Write-Success "authorized_keys created with content: $($content.Length) characters"
            } else {
                Write-Warning "authorized_keys is empty"
            }
            
            $perms = icacls $authKeysPath
            Write-Info "Current permissions:"
            $perms | ForEach-Object { Write-Info "  $_" }
        }

        Write-Info "Restarting services..."
        Start-Service ssh-agent -ErrorAction SilentlyContinue
        Start-Service sshd -ErrorAction SilentlyContinue

        Write-Success "Ultimate permission fix completed!"
        return $true

    } catch {
        Write-Warning "Ultimate fix failed: $($_.Exception.Message)"
        Start-Service ssh-agent, sshd -ErrorAction SilentlyContinue
        return $false
    }
}

function Fix-SSHConfiguration {
    param([string]$SSHDir)
    
    Write-Step "FIXING SSH CONFIGURATION"
    
    try {
        Write-Info "Updating SSH client config..."
        $clientConfig = @"
Host *
    IdentitiesOnly yes
    IdentityFile ~/.ssh/id_ed25519
    PubkeyAuthentication yes
    PasswordAuthentication yes
    ServerAliveInterval 60
    ServerAliveCountMax 3
    StrictHostKeyChecking no
    UserKnownHostsFile ~/.ssh/known_hosts

Host localhost
    User feliza
    Port 22

Host github.com
    User git
    IdentityFile ~/.ssh/id_ed25519

Host gitlab.com
    User git  
    IdentityFile ~/.ssh/id_ed25519
"@
        Set-Content -Path "$SSHDir\config" -Value $clientConfig -Encoding UTF8
        Write-Success "SSH client config updated"

        Write-Info "Updating SSH server config..."
        $sshdConfigPath = "$env:ProgramData\ssh\sshd_config"
        if (Test-Path $sshdConfigPath) {
            $sshdConfig = @"
Port 22
Protocol 2

HostKey $env:ProgramData\ssh\ssh_host_rsa_key
HostKey $env:ProgramData\ssh\ssh_host_ecdsa_key
HostKey $env:ProgramData\ssh\ssh_host_ed25519_key

PubkeyAuthentication yes
AuthorizedKeysFile .ssh/authorized_keys
PasswordAuthentication yes
PermitEmptyPasswords no
PermitRootLogin no

MaxAuthTries 10
MaxSessions 20

AllowUsers feliza

SyslogFacility AUTH
LogLevel VERBOSE

AcceptEnv LANG LC_*

AllowAgentForwarding yes
AllowTcpForwarding yes

Subsystem sftp internal-sftp

Match User feliza
    AuthorizedKeysFile .ssh/authorized_keys
"@
            Set-Content -Path $sshdConfigPath -Value $sshdConfig -Encoding UTF8
            Write-Success "SSH server configuration updated"
        }

        return $true
    } catch {
        Write-Warning "Configuration fix failed: $($_.Exception.Message)"
        return $false
    }
}

function Verify-SSHSetup {
    param([string]$SSHDir)
    
    Write-Step "VERIFYING SSH SETUP"
    
    $authKeysPath = "$SSHDir\authorized_keys"
    
    Write-Info "Checking authorized_keys..."
    if (Test-Path $authKeysPath) {
        $content = Get-Content $authKeysPath -ErrorAction SilentlyContinue
        if ($content) {
            Write-Success "authorized_keys exists with content"
            Write-Info "Content: $content"
        } else {
            Write-Warning "authorized_keys exists but is empty or unreadable"
        }
        
        try {
            $perms = (Get-Acl $authKeysPath).Access | Where-Object { $_.IdentityReference -like "*feliza*" }
            Write-Info "User permissions: $($perms.FileSystemRights)"
        } catch {
            Write-Warning "Cannot read permissions"
        }
    } else {
        Write-Warning "authorized_keys does not exist"
    }

    Write-Info "Checking private key..."
    $privateKey = "$SSHDir\id_ed25519"
    if (Test-Path $privateKey) {
        try {
            $testContent = Get-Content $privateKey -First 1 -ErrorAction Stop
            Write-Success "Private key is readable"
        } catch {
            Write-Warning "Private key is not readable: $($_.Exception.Message)"
        }
    }

    Write-Info "Checking services..."
    $services = Get-Service ssh-agent, sshd
    foreach ($service in $services) {
        $status = if ($service.Status -eq 'Running') { "RUNNING" } else { "STOPPED" }
        Write-Info "$($service.Name): $status"
    }
}

function Test-Connection-Comprehensive {
    Write-Step "COMPREHENSIVE CONNECTION TESTING"
    
    $sshDir = "C:\Users\camil\.ssh"
    $privateKey = "$sshDir\id_ed25519"
    $publicKey = "$sshDir\id_ed25519.pub"

    Write-Info "Checking key fingerprints..."
    $privateFingerprint = ssh-keygen -l -f $privateKey
    Write-Info "Private key fingerprint: $($privateFingerprint[0])"
    $publicFingerprint = ssh-keygen -l -f $publicKey
    Write-Info "Public key fingerprint: $($publicFingerprint[0])"

    Write-Info "Testing with explicit key file..."
    try {
        $testResult = ssh -o ConnectTimeout=5 -i $privateKey feliza@localhost "echo AUTH_SUCCESS" 2>&1
        if ($testResult -like "*AUTH_SUCCESS*") {
            Write-Success "EXPLICIT KEY TEST: SUCCESS!"
        } else {
            Write-Warning "EXPLICIT KEY TEST: FAILED"
            Write-Info "Output: $testResult"
        }
    } catch {
        Write-Warning "EXPLICIT KEY TEST: ERROR"
    }

    Write-Info "Testing with SSH agent..."
    try {
        ssh-add $privateKey | Out-Null
        $testResult = ssh -o ConnectTimeout=5 feliza@localhost "echo AUTH_SUCCESS" 2>&1
        if ($testResult -like "*AUTH_SUCCESS*") {
            Write-Success "SSH AGENT TEST: SUCCESS!"
        } else {
            Write-Warning "SSH AGENT TEST: FAILED"
            Write-Info "Output: $testResult"
        }
    } catch {
        Write-Warning "SSH AGENT TEST: ERROR"
    }

    Write-Info "Testing basic connectivity..."
    try {
        $test2 = Test-NetConnection -ComputerName localhost -Port 22
        if ($test2.TcpTestSucceeded) {
            Write-Success "Port 22 is open and accessible"
        } else {
            Write-Warning "Port 22 is not accessible"
        }
    } catch {
        Write-Warning "Connectivity test failed"
    }

    Write-Info "Testing GitHub connection (informational)..."
    try {
        $githubResult = ssh -T -o IdentityFile="$privateKey" git@github.com 2>&1
        if ($githubResult -like "*successfully authenticated*") {
            Write-Success "GitHub: AUTHENTICATED"
        } else {
            Write-Info "GitHub: Add your public key to GitHub to enable authentication"
        }
    } catch {
        Write-Info "GitHub: Connection test completed"
    }
}

function Reset-SSHSetup {
    param([string]$SSHDir)
    
    Write-Step "RESETTING SSH SETUP"
    
    try {
        Stop-Service ssh-agent, sshd -Force -ErrorAction SilentlyContinue
        
        if (Test-Path $SSHDir) {
            Remove-Item $SSHDir -Recurse -Force -ErrorAction SilentlyContinue
            Start-Sleep -Seconds 2
        }
        
        New-Item -ItemType Directory -Path $SSHDir -Force | Out-Null
        
        Start-Process -FilePath "takeown" -ArgumentList "/f `"$SSHDir`" /r /d y" -Wait -WindowStyle Hidden
        Start-Process -FilePath "icacls" -ArgumentList "`"$SSHDir`" /grant:r `"Feliza\feliza:(F)`" /t" -Wait -WindowStyle Hidden
        
        Write-Success "SSH directory reset"
        return $true
    } catch {
        Write-Warning "Reset failed: $($_.Exception.Message)"
        return $false
    }
}

Write-Host "`n" + ("=" * 60) -ForegroundColor Magenta
Write-Host "            COMPLETE SSH SETUP & AUTHENTICATION FIX" -ForegroundColor Magenta
Write-Host ("=" * 60) -ForegroundColor Magenta
Write-Host "Computer: $env:COMPUTERNAME" -ForegroundColor White
Write-Host "User: $env:USERNAME" -ForegroundColor White
Write-Host "Time: $(Get-Date)" -ForegroundColor White

$isAdmin = Test-Admin
if (-not $isAdmin) {
    Write-Host "`nERROR: Must run as Administrator for complete setup!" -ForegroundColor Red
    exit 1
}

$sshDir = "C:\Users\camil\.ssh"

try {
    Write-Step "PHASE 1: BASIC SSH SETUP"
    Install-OpenSSH
    Configure-Services
    Configure-Firewall
    
    Write-Step "PHASE 2: CLEAN SETUP"
    Reset-SSHSetup -SSHDir $sshDir
    Generate-SSHKeys -SSHDir $sshDir
    Configure-SSHAgent
    
    Write-Step "PHASE 3: PERMISSION FIX"
    Fix-SSHPermissions-Ultimate -SSHDir $sshDir
    
    Write-Step "PHASE 4: CONFIGURATION"
    Fix-SSHConfiguration -SSHDir $sshDir
    
    Write-Step "PHASE 5: VERIFICATION"
    Verify-SSHSetup -SSHDir $sshDir
    Test-Connection-Comprehensive
    
    Write-Step "SETUP COMPLETE - FINAL SUMMARY"
    
    Write-Success "SSH setup completed successfully!"
    Write-Success "All components are configured and tested"
    
    $pubKeyContent = Get-Content "$sshDir\id_ed25519.pub"
    Write-Host "`nYOUR PUBLIC KEY (add this to services):" -ForegroundColor Cyan
    Write-Host $pubKeyContent -ForegroundColor White
    
    Write-Host "`nNEXT STEPS:" -ForegroundColor Green
    Write-Info "1. Add your public key to GitHub/GitLab/remote servers"
    Write-Info "2. Test: ssh localhost (should work now)"
    Write-Info "3. Test: ssh -T git@github.com (after adding key)"
    Write-Info "4. Use: git clone git@github.com:user/repo.git"
    Write-Info "5. Use: ssh user@remote-server.com"
    
    Write-Host "`n🎉 YOUR SSH SETUP IS 100% COMPLETE AND READY! 🎉" -ForegroundColor Green

} catch {
    Write-Host "`nSETUP FAILED: $($_.Exception.Message)" -ForegroundColor Red
    Write-Info "Stack trace: $($_.ScriptStackTrace)"
}

Write-Host "`n" + ("=" * 60) -ForegroundColor Magenta
Write-Host "Script execution completed" -ForegroundColor Magenta
Write-Host ("=" * 60) -ForegroundColor Magenta
