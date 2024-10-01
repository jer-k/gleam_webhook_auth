# webhook_auth

## About

This is a simple Gleam program that uses `mist` to create a webserver which can receive
webhooks from GitHub and authenticate them. If the authentication passes, we will return
a 200, otherwise we'll return a 401.

## Running the program
```sh
WEBHOOK_SECRET=your_secret gleam run
```
