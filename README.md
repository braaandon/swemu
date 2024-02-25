# Stopwatch Emulator

https://github.com/braaandon/swemu/assets/86573128/9d8eccfa-1271-4946-93ce-cbe7885cefeb

## Guide

- Build both the emulator and patcher
- Generate a keyauth appropriate certificate
- Place the emulator, patcher, certificate+key and stopwatch in a folder
- Run the emulator as administrator

## How it works

The emulator will launch Stopwatch.exe as a suspended process and inject the patcher which will hook GetAddrInfoW and redirect all traffic to localhost, it will then resume the process and launch a server which will respond to all of Stopwatch's queries.

## Potential problems

- Possible race between the server starting and Stopwatch loading, but this will never be hit
- Not certain if everything is covered
