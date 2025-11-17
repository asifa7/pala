@echo off
REM Start Elasticsearch in a new cmd window
start "Elasticsearch" cmd /k "C:\asif pala\elasticsearch-9.1.0\bin\elasticsearch.bat"

REM Start Kibana in a new cmd window
start "Kibana" cmd /k "C:\asif pala\kibana-9.1.0-windows-x86_64\kibana-9.1.0\bin\kibana.bat"

echo Elasticsearch and Kibana started in separate windows.
exit /b 0
