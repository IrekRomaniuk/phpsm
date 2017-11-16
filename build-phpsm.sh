#!/usr/bin/bash
env GOOS=linux GOARCH=386 go build -o bin/phpsm_lin
env GOOS=windows GOARCH=386 go build -o bin/phpsm_win