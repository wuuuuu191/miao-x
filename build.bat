@echo off
REM Build all platform binaries (pure Go, static, CGO off)
cd /d "%~dp0"
where go >nul 2>&1
if %errorlevel%==0 (
  echo [build] using go from PATH
) else if exist "C:\go-toolchain\bin\go.exe" (
  echo [build] using bundled toolchain
  set "PATH=C:\go-toolchain\bin;%PATH%"
) else (
  echo [build] ERROR: go not found in PATH nor C:\go-toolchain
  exit /b 1
)
set "CGO_ENABLED=0"
set "LDFLAGS=-s -w"

set "GOOS=linux" & set "GOARCH=amd64"
go build -trimpath -ldflags="%LDFLAGS%" -o release\miaowu-linux-amd64 ./cmd/miaowu || exit /b 1
set "GOOS=linux" & set "GOARCH=arm64"
go build -trimpath -ldflags="%LDFLAGS%" -o release\miaowu-linux-arm64 ./cmd/miaowu || exit /b 1
set "GOOS=windows" & set "GOARCH=amd64"
go build -trimpath -ldflags="%LDFLAGS%" -o miaowu.exe ./cmd/miaowu || exit /b 1
echo ALL_BUILDS_OK
