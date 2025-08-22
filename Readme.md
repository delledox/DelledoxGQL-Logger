# Burp Suite GraphQL Logger

A Burp Suite extension by **Delledox Security** to log and inspect GraphQL traffic.  
Adds a **DelledoxGQL Logger** tab in Burp to view requests and responses with operation names and status codes.

---

## Features
- Captures all `/graphql` requests
- Shows Host, Method, URL, Operation Name, and Status
- View request & response in Burp’s editors
- Auto-links responses to requests

---

## Installation
1. Download [Jython standalone JAR](https://www.jython.org/download).
2. In Burp: `Extender → Options → Python Environment` → set Jython JAR.
3. Add extension: `Extender → Extensions → Add` → choose `graphql_logger.py`.

---

## Usage
- Open the **GraphQL Logger** tab.
- Table auto-populates with GraphQL traffic.
- Select a row to inspect request/response.
- Status column shows HTTP codes (200, 400, 500, etc.).

---

## About
Built by **Delledox Security**  
Focused on mobile and cloud security research & tooling.

---

## License
MIT License
