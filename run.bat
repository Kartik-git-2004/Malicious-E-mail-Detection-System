@echo off
echo Compiling and running Malicious Email Detection System...

REM Compile all Java files
javac -d target/classes -cp "target/classes;lib/*" src/main/java/com/emailsecurity/Main.java

REM Run the application
java -cp "target/classes;lib/*" com.emailsecurity.Main

pause 