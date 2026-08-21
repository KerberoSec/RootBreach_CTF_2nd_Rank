# RootBreach CTF 2nd Rank

## Overview

This repository contains the complete source code and infrastructure configuration for a Capture The Flag challenge environment named HRS Admin Router. The project simulates a home router administration panel that is composed of several cooperating services, including a reverse proxy layer, a traffic inspection proxy, a web server running two separate Flask applications, and a relational database. The environment is fully containerized using Docker and is orchestrated through a single Dockerfile along with a docker compose definition, making it possible to build and run the entire challenge stack with minimal setup.

The purpose of this project is to provide a realistic, multi layered target that mirrors how a small internet of things device or home networking product might expose both a public facing administration website and a private internal API used for hardware level status reporting. The challenge is designed around the interaction between the reverse proxy, the traffic inspection proxy, and the web application server, and it requires an understanding of how Host header based routing, session handling, and access control decisions are made across that chain of services.

## Table of Contents

1. Background and Purpose
2. System Architecture
3. Request Flow
4. Technology Stack
5. Project Structure
6. Component Descriptions
7. Security Measures and Fixes Documented in the Source
8. Default Application Accounts
9. Ports Reference
10. Environment Variables and Build Arguments
11. Getting Started
12. Running the Environment with the Makefile
13. Notes on the Flag Mechanism
14. Disclaimer

## Background and Purpose

This repository documents the work carried out during RootBreach, a Capture The Flag event organized by the Cybersecurity Club of Dr B R Ambedkar National Institute of Technology Jalandhar. As part of the event, the organizers distributed a zip archive containing the source code of a simulated home router administration panel. The archive, as provided, contained a number of intentionally introduced security vulnerabilities spread across its web application code and its infrastructure configuration.

After receiving the archive, the environment was first set up and run locally so that its behavior could be observed directly rather than assumed from reading the code alone. A manual source code review was then carried out across every service in the stack, including the two Flask applications, the Apache configuration, the HAProxy configuration, and the mitmproxy setup, alongside manual penetration testing of the running application to confirm that each suspected weakness was genuinely exploitable. Once the vulnerabilities were identified and understood, each one was fixed directly in the source code. The corrected environment was then rebuilt, tested again to confirm that the fixes held and that the application still functioned correctly, and finally hosted for review. This repository is the exact codebase that was uploaded to GitHub following that process, and the inline comments left throughout the code describe, file by file, the vulnerability that was originally present, the risk it introduced, and the fix that was applied to remove it.

Working through this exercise, the team placed second in the RootBreach CTF event, which is reflected in the name of this repository.

## System Architecture

The environment is built from five logical services that run together inside a single container, coordinated by supervisord, with corresponding standalone Dockerfiles also provided for each service so that they can be understood or deployed independently if needed.

1. HAProxy, listening on port 8001, acts as the first point of contact for traffic that is intended to be routed based on the Host header of the incoming request. It exposes a health check endpoint and decides which backend a request should be forwarded to.
2. mitmproxy, listening on port 8002, sits in reverse proxy mode in front of the main web server and is used to inspect or manipulate HTTP traffic as it passes through the chain.
3. Apache HTTPD, configured with mod_wsgi, listens on port 80 and hosts two separate virtual hosts on the same port, distinguished from one another purely by the ServerName directive and the Host header of the incoming request.
4. The external Flask application, referred to in the code as hrs_admin_router, implements the public facing router administration website, including login, dashboard, administration panel, and WiFi settings pages.
5. The internal Flask application, referred to in the code as internal_router, implements a set of internal device status endpoints that describe simulated hardware components of the router, one of which exposes the value of the challenge flag.
6. MariaDB, running locally inside the main container, provides persistent storage for user accounts and for server side session data used by the external website.

A standalone MySQL 5.7 Dockerfile is also included in the mysql directory for reference or for use in an alternative deployment topology, although the primary Dockerfile at the root of the repository provisions MariaDB directly inside the combined application container.

## Request Flow

A typical request entering the environment follows this path.

1. A client sends an HTTP request to port 8001, which is served by HAProxy.
2. HAProxy inspects the Host header of the request. If the Host header is set to internal.router, the request is forwarded to the router_internal backend. Otherwise it is forwarded to the router_external backend by default.
3. Both backends currently point at the same downstream address and port, which is the mitmproxy service listening on port 8002 in front of the Apache server on port 80. Additional response headers are appended by HAProxy when the internal backend is selected, including X Forwarded Host, X Upstream Proxy, and Via, which disclose information about the proxy chain.
4. mitmproxy forwards the request to Apache on port 80 in reverse proxy mode.
5. Apache selects one of its two configured virtual hosts based on the ServerName that matches the Host header of the request. The virtual host bound to localhost serves the external hrs_admin_router Flask application, while the virtual host bound to internal.router serves the internal_router Flask application.
6. The external application handles authentication, session verification, and rendering of the login, dashboard, administration panel, and WiFi settings pages, and communicates with MariaDB for both user records and session storage.
7. The internal application returns plain text descriptions of simulated hardware devices, including CPU, memory, storage, WiFi chipset, Bluetooth, Ethernet, and a flag device, with the flag device endpoint reading and returning the contents of the flag file that is baked into the image at build time.

This layered routing design, in which access to the internal application is intended to be gated by Host header inspection at the HAProxy layer rather than by any authentication mechanism at the internal application itself, forms the core of the challenge.

## Technology Stack

The project combines the following technologies.

* Python 3 with the Flask microframework for both the external and internal web applications
* Flask SQLAlchemy for database modelling and object relational mapping
* Flask Session for server side session storage backed by SQLAlchemy
* Flask WTF for cross site request forgery protection
* Werkzeug for password hashing and verification
* PyMySQL as the database driver used by SQLAlchemy to connect to MariaDB
* Apache HTTPD with mod_wsgi for serving the Flask applications through name based virtual hosting
* HAProxy version 2.0.5 for Host header based reverse proxy routing
* mitmproxy version 6.0.2 for HTTP traffic interception in reverse proxy mode
* MariaDB, installed directly inside the main application image, for relational storage
* MySQL 5.7, provided as an alternative standalone container definition
* Supervisor for managing and supervising all of the service processes within a single container
* Bootstrap and jQuery for the front end presentation layer of the external website
* Docker and Docker Compose for building and orchestrating the environment

## Project Structure

```
RootBreach_CTF_2nd_Rank
│
├── Dockerfile
├── Makefile
├── docker-compose.yml
├── supervisord.conf
│
├── app
│   ├── Dockerfile
│   ├── hrs_admin_router-httpd.conf
│   │
│   ├── internal
│   │   ├── requirements.txt
│   │   ├── run.py
│   │   ├── internal_router.wsgi
│   │   └── app
│   │       ├── __init__.py
│   │       └── routes.py
│   │
│   └── website
│       ├── requirements.txt
│       ├── run.py
│       ├── hrs_admin_router.wsgi
│       └── app
│           ├── __init__.py
│           ├── db.py
│           ├── models.py
│           ├── routes.py
│           │
│           ├── static
│           │   ├── css
│           │   │   └── bootstrap.min.css
│           │   └── js
│           │       ├── bootstrap.min.js
│           │       └── jquery-3.5.1.min.js
│           │
│           └── templates
│               ├── admin_panel.html
│               ├── dashboard.html
│               ├── login.html
│               └── wifi_settings.html
│
├── haproxy
│   ├── Dockerfile
│   └── haproxy.cfg
│
├── mitmproxy
│   └── Dockerfile
│
└── mysql
    └── Dockerfile
```

Each top level folder maps directly to one service in the architecture. The app folder contains both Flask applications together with the Apache configuration that serves them, the haproxy and mitmproxy folders each contain a standalone Dockerfile for their respective proxy service, and the mysql folder contains a standalone Dockerfile for the database service. The root level Dockerfile, docker-compose.yml, and supervisord.conf tie all of these pieces together into a single runnable environment.

## Component Descriptions

### Root Level Files

The root Dockerfile is the primary build definition for the challenge. It installs MariaDB, Apache, mod_wsgi, Python, HAProxy, supervisor, and mitmproxy inside a single Debian bullseye slim image. It copies both Flask applications into their respective directories under the Apache web root, accepts a FLAG build argument that is written into a file at the root of the filesystem, installs the Apache virtual host configuration, initializes the MariaDB data directory, installs the HAProxy configuration as a template, and generates an entrypoint script that starts MariaDB temporarily to configure the root password and create the application database before finally launching supervisord to manage all long running processes.

The Makefile includes a shared common makefile from a parent directory, which suggests that this repository is designed to be used as a subdirectory within a larger collection of challenges that share common build and deployment tooling.

The docker-compose.yml file defines a single service named app, built from the root Dockerfile with the FLAG build argument supplied, exposing ports 80, 8001, and 8002, and configured with a health check that polls the root of the web server on port 80.

The supervisord.conf file defines the startup order and monitoring configuration for every process running inside the container, starting with MariaDB, followed by a wait step that blocks until MariaDB is ready to accept connections, then HAProxy, then mitmproxy, and finally Apache.

### HAProxy Layer

The haproxy directory contains a standalone Dockerfile based on the official haproxy 2.0.5 image, along with the haproxy.cfg configuration file. The configuration defines a global section with logging and connection limits, a defaults section with timeout values and reliance on the modern HTX request parser, a frontend listening on port 8001 that performs Host header based access control lists to select between two backends, and two backend definitions, router_internal and router_external, both of which forward to the same upstream address using the safe HTTP connection reuse policy.

### mitmproxy Layer

The mitmproxy directory contains a standalone Dockerfile based on the official mitmproxy 6.0.2 image. It installs the gettext base package so that environment variables can be substituted into the reverse proxy target address at container start time, and it launches mitmdump in reverse proxy mode on port 8002, forwarding traffic to the configured upstream server and port.

### Apache and Application Server Layer

The app directory contains a dedicated Dockerfile that can build the web tier independently of the database and proxy tiers, along with the hrs_admin_router-httpd.conf Apache configuration file. This configuration defines two virtual hosts that both listen on port 80. The first virtual host is bound to the ServerName localhost and serves the external hrs_admin_router Flask application as a WSGI daemon process, with cross origin resource sharing restricted to a single trusted origin placeholder. The second virtual host is bound to the ServerName internal.router and serves the internal_router Flask application as a separate WSGI daemon process, with cross origin resource sharing set to null so that no browser based cross origin requests are permitted. Both virtual hosts explicitly disable directory listing and restrict configuration overrides.

### External Website Application

The website subdirectory implements the public facing router administration panel.

The __init__.py module initializes the Flask application, configures a randomly generated secret key when one is not supplied through the environment, connects to the MariaDB database using PyMySQL with the READ COMMITTED transaction isolation level, configures server side sessions backed by SQLAlchemy with signed, HTTP only, same site cookies, enables cross site request forgery protection with a one hour token lifetime, creates the database schema on startup, and seeds two default accounts, one administrator and one standard user, using securely hashed passwords.

The db.py module exposes a shared SQLAlchemy instance that is used by the rest of the application.

The models.py module defines the User model, including username, hashed password, name, last name, email address, and an is_admin boolean flag that defaults to false in accordance with the principle of least privilege.

The routes.py module implements the application routes. The root path redirects to the login page. The login route accepts a username and password, validates the username against a strict alphanumeric pattern, verifies the password against the stored hash, clears any prior session before establishing a new one to prevent session fixation, and returns a generic error message on failure so that valid usernames cannot be enumerated from the response. The logout route fully clears the session. The dashboard route requires a valid, verified session. The admin_panel route requires both a valid session and an is_admin flag set to true on the corresponding user record, returning a forbidden response with an access denied message when a non administrator attempts to reach it. The wifi_settings route requires a valid session, validates the submitted network name against an allowed character pattern, and always responds that settings cannot be changed because the WiFi chipset is still booting, which ties into the narrative exposed by the internal application. A global after request handler attaches a consistent set of security related response headers to every response produced by the application, including cache control directives that prevent sensitive pages from being cached, along with content type, frame, cross site scripting, and referrer policy headers.

The templates directory contains the four HTML pages rendered by the application: the login form, the authenticated user dashboard, the administrator only panel, and the WiFi settings page, all sharing a consistent dark themed Bootstrap based visual style.

The static directory bundles local copies of Bootstrap and jQuery so that the front end does not depend on any external content delivery network at runtime.

### Internal Router Application

The internal subdirectory implements a minimal Flask application intended to represent firmware level status reporting for the simulated router hardware. It exposes a general devices listing endpoint describing the state of the central processing unit, memory, storage, WiFi chipset, Bluetooth, Ethernet, and flag components, individual status endpoints for each of those components, and a flag status endpoint that reads the contents of the flag file written into the image at build time and includes it directly in a plain text response formatted to resemble a bootloader log. This application performs no authentication or authorization of its own and instead relies entirely on the assumption that it will only ever be reached through the proxy chain when the Host header presented to Apache is internal.router, which in turn is only expected to happen when HAProxy has been instructed to route a request to the internal backend.

### Database Layer

The mysql directory provides a standalone Dockerfile based on the official MySQL 5.7 image, pre configured with a root password and an initial database name matching the values expected by the Flask application configuration, for use in deployment scenarios where the database is run as a separate container rather than embedded in the combined application image.

## Security Measures and Fixes Documented in the Source

The source code throughout this repository contains extensive inline documentation describing security issues that were identified in an earlier version of the challenge and the corresponding remediation that was applied. A summary of the most significant measures is provided below.

* The Flask secret key used for signing session data was changed from a hardcoded, predictable value to a cryptographically generated value with two hundred fifty six bits of entropy, configurable through an environment variable in production.
* Session storage was moved from the default client side cookie based mechanism to server side storage in the database, with cookies marked HTTP only and same site to reduce the impact of cross site scripting and cross site request forgery.
* Cross site request forgery protection was enabled globally for the external application, with a bounded token validity window.
* User passwords are stored using Werkzeug's password hashing utilities rather than in plain text, and are verified using a constant time comparison function.
* The database connection was configured to use the READ COMMITTED isolation level rather than the less strict READ UNCOMMITTED level, reducing the risk of dirty reads.
* User supplied input for both the login form and the WiFi settings form is sanitized and validated against strict character and length rules before being used anywhere in the application.
* The administration panel route now explicitly checks the is_admin flag on the authenticated user before rendering privileged content, closing a privilege escalation path that previously allowed any authenticated user to reach it.
* Login failures return a single generic error message regardless of whether the username exists, reducing the risk of user enumeration.
* The logout route clears the entire session rather than removing a single key, ensuring that no partially authenticated state remains afterward.
* A consistent set of HTTP security response headers is applied to every response from the external application, including protections against MIME type sniffing, clickjacking, and browser side content caching of sensitive pages.
* Dangerous Flask features that can lead to server side template injection or command execution, specifically render_template_string and subprocess, were removed from both applications.
* The Apache configuration was corrected to use properly cased directives, valid WSGI process names, explicit ServerName values for both virtual hosts, restrictive cross origin resource sharing headers, and disabled directory listing.
* The HAProxy configuration was updated to rely on the modern HTX request parser rather than the legacy parser, which mitigates a class of HTTP request smuggling issues associated with content length and transfer encoding desynchronization, and connection reuse was changed from an unconditionally aggressive mode to a safer mode.

Despite these fixes, the internal_router application still performs no authentication of its own and continues to rely solely on network level routing decisions made upstream, which is the intended design of the challenge and the area that a participant is expected to explore.

## Default Application Accounts

The external website seeds two accounts automatically the first time the application starts, provided that they do not already exist in the database.

| Username | Password | Administrator |
|----------|----------|----------------|
| admin    | admin123 | Yes            |
| user     | user123  | No             |

These credentials are intended for use within the challenge environment only and should never be reused in any production system.

## Ports Reference

| Port | Service     | Purpose                                                         |
|------|-------------|------------------------------------------------------------------|
| 80   | Apache      | Serves both the external and internal Flask applications         |
| 8001 | HAProxy     | Public entry point that routes based on the Host header          |
| 8002 | mitmproxy   | Reverse proxy that inspects traffic between HAProxy and Apache    |
| 3306 | MariaDB or MySQL | Database service, used internally or by the standalone MySQL container |

## Environment Variables and Build Arguments

| Name | Location | Purpose |
|------|----------|---------|
| FLAG | Docker build argument | Value written to the flag file at image build time and later exposed through the internal router's flag status endpoint |
| SECRET_KEY | Runtime environment variable, optional | Overrides the automatically generated Flask secret key for the external application |
| SERVER_HOSTNAME | Supervisor environment, defaults to 127.0.0.1 | Upstream address that HAProxy forwards requests to |
| SERVER_PORT | Supervisor environment, defaults to 80 | Upstream port that HAProxy forwards requests to |
| MYSQL_ROOT_PASSWORD | Standalone MySQL Dockerfile | Root password for the standalone database container |
| MYSQL_DATABASE | Standalone MySQL Dockerfile | Initial database name for the standalone database container |

## Getting Started

The following steps describe how to build and run the environment locally using Docker and Docker Compose.

1. Ensure Docker and Docker Compose are installed on the host machine.
2. From the root of this repository, build and start the environment by running docker compose up, optionally supplying a real flag value by overriding the FLAG build argument in the docker-compose.yml file or on the command line.
3. Once the health check reports a healthy status, the external website will be reachable on port 80 or through the HAProxy front end on port 8001, and the mitmproxy front end will be reachable on port 8002.
4. Authenticate to the external website using either of the default accounts described above to explore the dashboard, WiFi settings, and administration panel functionality.
5. Investigate the relationship between the Host header, HAProxy's routing rules, and the two Apache virtual hosts in order to understand how a request can reach the internal_router application and its flag status endpoint.

## Running the Environment with the Makefile

The included Makefile includes a shared common.mk file from a parent directory, which implies this project is intended to be dropped into a larger challenge collection that provides shared build, test, and deployment targets. When used within such a collection, the standard make targets provided by that shared makefile can be used to build and run this challenge alongside others in a consistent manner. When used outside of that collection, the docker compose workflow described above can be used directly instead.

## Notes on the Flag Mechanism

The flag value is supplied at image build time through the FLAG build argument and is written to a file at the root of the container filesystem. The internal_router application reads this file at request time and includes its contents in the response body of the devices flag status endpoint, formatted to resemble an unrelated hardware boot log. Successfully retrieving this value requires reaching the internal_router application through the correct combination of Host header and proxy routing rather than accessing it directly, which is the central objective of the challenge.

## Disclaimer

This repository is provided strictly for educational purposes and for use within controlled Capture The Flag competition environments. The applications, credentials, and configurations contained here are intentionally simplified or made vulnerable in certain respects to support a learning exercise and must not be deployed on any publicly accessible or production system. Anyone using this repository is responsible for ensuring that it is only run within an isolated, authorized environment.
