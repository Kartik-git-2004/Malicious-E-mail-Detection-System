@echo off
echo Downloading required dependencies...

REM Create lib directory if it doesn't exist
if not exist lib mkdir lib

REM Download dependencies
powershell -Command "& {Invoke-WebRequest -Uri 'https://repo1.maven.org/maven2/com/sun/mail/javax.mail/1.6.2/javax.mail-1.6.2.jar' -OutFile 'lib/javax.mail-1.6.2.jar'}"
powershell -Command "& {Invoke-WebRequest -Uri 'https://repo1.maven.org/maven2/org/json/json/20231013/json-20231013.jar' -OutFile 'lib/json-20231013.jar'}"
powershell -Command "& {Invoke-WebRequest -Uri 'https://repo1.maven.org/maven2/commons-validator/commons-validator/1.7/commons-validator-1.7.jar' -OutFile 'lib/commons-validator-1.7.jar'}"
powershell -Command "& {Invoke-WebRequest -Uri 'https://repo1.maven.org/maven2/org/apache/commons/commons-lang3/3.14.0/commons-lang3-3.14.0.jar' -OutFile 'lib/commons-lang3-3.14.0.jar'}"
powershell -Command "& {Invoke-WebRequest -Uri 'https://repo1.maven.org/maven2/commons-io/commons-io/2.15.1/commons-io-2.15.1.jar' -OutFile 'lib/commons-io-2.15.1.jar'}"
powershell -Command "& {Invoke-WebRequest -Uri 'https://repo1.maven.org/maven2/org/apache/opennlp/opennlp-tools/2.3.1/opennlp-tools-2.3.1.jar' -OutFile 'lib/opennlp-tools-2.3.1.jar'}"
powershell -Command "& {Invoke-WebRequest -Uri 'https://repo1.maven.org/maven2/nz/ac/waikato/cms/weka/weka-stable/3.8.6/weka-stable-3.8.6.jar' -OutFile 'lib/weka-stable-3.8.6.jar'}"

echo Dependencies downloaded successfully!
echo You can now run the application using run.bat
pause 