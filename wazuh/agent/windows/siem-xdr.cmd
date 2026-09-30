@echo off
rem Script active response cua siem-xdr cho Wazuh agent Windows (A001 PC-01).
rem Chep siem-xdr.cmd va siem-xdr.ps1 vao "C:\Program Files (x86)\ossec-agent\active-response\bin\".
rem wazuh-execd (chay bang SYSTEM) goi file nay, stdin la 1 dong JSON -> chuyen nguyen cho PowerShell.
powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -File "%~dp0siem-xdr.ps1"
