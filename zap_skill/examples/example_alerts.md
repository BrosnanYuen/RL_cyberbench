# ZAP alerts digest — 3 alert(s)

## High (1)

### SQL Injection

- **risk: High · confidence: Medium · CWE-89 · WASC-19**
- **URL**: `http://192.161.7.1:8080/?q=1%27%20OR%201=1`
- **Instances**:
  - `GET` http://192.161.7.1:8080/?q=1%27%20OR%201=1 · param=`q` · attack=`1' OR 1=1` · evidence=`UNION`
- **Description**: SQL injection may be possible. The UNION keyword was detected in the response.
- **Solution**: Do not construct SQL queries with string concatenation; use parameterized queries or an ORM.

## Medium (1)

### Application Error Disclosure

- **risk: Medium · confidence: Medium · CWE-209 · WASC-13**
- **URL**: `http://192.161.7.1:8080/?q=%25`
- **Instances**:
  - `GET` http://192.161.7.1:8080/?q=%25 · param=`q` · attack=`%` · evidence=`Internal Server Error`
- **Description**: The application disclosed an internal error page that may leak implementation details.
- **Solution**: Return generic error pages and log details server-side only.

## Low (1)

### Server Header Information Disclosure

- **risk: Low · confidence: High · CWE-200 · WASC-13**
- **URL**: `http://192.161.7.1:8080/`
- **Instances**:
  - `GET` http://192.161.7.1:8080/ · evidence=`Server: nginx/1.25.3`
- **Description**: The Server response header discloses the server software and version.
- **Solution**: Remove or mask the Server header.
