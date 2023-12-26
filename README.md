
# Personal Server
This repository contains the base files for the CS 3214
"Personal Secure Server" project.

The implementation is written in http.c and main.c.
The simple HTTP server supports html, gif, png, jpg, js, css, mp4, svg files (static file serving) and parses http requests with basic authentication through JWT (JSON Web Tokens), and an API for user login, logout, and video listing.

- `src` - contains the base code's source files.
- `tests` - contains unit tests, performance tests, and associated files.
- `react-app` - contains a JavaScript web app.
- `sfi` - contains documentation for the 'server fuzzing interface'.

## Get Started
Run the script: `./install-dependencies.sh`. Then, `cd` into `src` and type `make` to build the base code.
